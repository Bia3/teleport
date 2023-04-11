// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package athena

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenaTypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	athenaTimestampFormat = "2006-01-02 15:04:05.999"
	iso8601DateFormat     = "2006-01-02"
)

// querier allows searching events on s3 using Athena engine.
// Data on s3 is stored in parquet files and partitioned by date using folders.
type querier struct {
	querierConfig

	log *log.Entry

	athenaCli *athena.Client
}

type querierConfig struct {
	tablename               string
	database                string
	workgroup               string
	queryResultsS3          string
	getQueryResultsInterval time.Duration
}

func newQuerier(cfg querierConfig, awsCfg aws.Config, log *log.Entry) *querier {
	return &querier{
		athenaCli:     athena.NewFromConfig(awsCfg),
		querierConfig: cfg,
		log:           log,
	}
}

func (q *querier) SearchEvents(fromUTC, toUTC time.Time, namespace string,
	eventTypes []string, limit int, order types.EventOrder, startKey string,
) ([]apievents.AuditEvent, string, error) {
	filter := searchEventsFilter{eventTypes: eventTypes}
	return q.searchEvents(context.TODO(), fromUTC, toUTC, limit, order, startKey, filter, "")
}

func (q *querier) SearchSessionEvents(fromUTC, toUTC time.Time, limit int,
	order types.EventOrder, startKey string, cond *types.WhereExpr, sessionID string,
) ([]apievents.AuditEvent, string, error) {
	// TODO(tobiaszheller): maybe if fromUTC is 0000-00-00, ask first last 30days and fallback to -inf - now-30
	// for sessionID != "". This kind of call is done on RBAC to check if user can access that session.
	filter := searchEventsFilter{eventTypes: []string{events.SessionEndEvent, events.WindowsDesktopSessionEndEvent}}
	if cond != nil {
		condFn, err := utils.ToFieldsCondition(cond)
		if err != nil {
			return nil, "", trace.Wrap(err)
		}
		filter.condition = condFn
	}
	return q.searchEvents(context.TODO(), fromUTC, toUTC, limit, order, startKey, filter, sessionID)
}

func (q *querier) searchEvents(ctx context.Context, fromUTC, toUTC time.Time, limit int,
	order types.EventOrder, startKey string, filter searchEventsFilter, sessionID string,
) ([]apievents.AuditEvent, string, error) {
	if limit <= 0 {
		limit = defaults.EventsIterationLimit
	}
	if limit > defaults.EventsMaxIterationLimit {
		return nil, "", trace.BadParameter("limit %v exceeds %v", limit, defaults.MaxIterationLimit)
	}

	var startKeyset *keyset
	if startKey != "" {
		var err error
		startKeyset, err = fromKey(startKey)
		if err != nil {
			return nil, "", trace.Wrap(err)
		}
	}

	query, params := prepareQuery(searchParams{
		fromUTC:     fromUTC,
		toUTC:       toUTC,
		order:       order,
		limit:       limit,
		startKeyset: startKeyset,
		filter:      filter,
		sessionID:   sessionID,
	}, q.tablename)

	q.log.WithField("query", query).
		WithField("params", params).
		WithField("startKey", startKey).
		Debug("Executing on Athena")

	queryId, err := q.startQueryExecution(ctx, query, params)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	if err := q.waitForSuccess(ctx, queryId); err != nil {
		return nil, "", trace.Wrap(err)
	}

	output, nextKey, err := q.fetchResults(ctx, queryId, limit, filter)
	return output, nextKey, trace.Wrap(err)
}

type searchEventsFilter struct {
	eventTypes []string
	condition  utils.FieldsCondition
}

type queryBuilder struct {
	builder strings.Builder
	args    []string
}

// withTicks wraps string with ticks.
// string params in athena need to be wrapped by "ticks".
func withTicks(in string) string {
	return fmt.Sprintf("'%s'", in)
}

func sliceWithTicks(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, withTicks(s))
	}
	return out
}

func (q *queryBuilder) Append(s string, args ...string) {
	q.builder.WriteString(s)
	q.args = append(q.args, args...)
}

func (q *queryBuilder) String() string {
	return q.builder.String()
}

func (q *queryBuilder) Args() []string {
	return q.args
}

type searchParams struct {
	fromUTC, toUTC time.Time
	limit          int
	order          types.EventOrder
	startKeyset    *keyset
	filter         searchEventsFilter
	sessionID      string
}

func prepareQuery(params searchParams, tablename string) (string, []string) {
	qb := &queryBuilder{}
	qb.Append(`SELECT DISTINCT uid, event_time, event_data FROM `)
	// tablename is validated during config validation.
	// It can only contain characters defined by Athena, which are safe from SQL
	// Injection.
	// Athena does not support passing table name as query parameters.
	qb.Append(tablename)
	qb.Append(` WHERE event_date BETWEEN date(?) AND date(?)`, withTicks(params.fromUTC.Format(iso8601DateFormat)), withTicks(params.toUTC.Format(iso8601DateFormat)))
	qb.Append(` AND event_time BETWEEN ? and ?`,
		fmt.Sprintf("timestamp '%s'", params.fromUTC.Format(athenaTimestampFormat)), fmt.Sprintf("timestamp '%s'", params.toUTC.Format(athenaTimestampFormat)))

	if params.sessionID != "" {
		qb.Append(" AND session_id = ?", withTicks(params.sessionID))
	}

	if len(params.filter.eventTypes) > 0 {
		// Athena does not support IN with single `?` and multiple parameters.
		// Based on number of eventTypes, first query is prepared with defined
		// number of placeholders. It's safe because we just taken len of event
		// types to query, values of event types are passed as parameters.
		eventsTypesInQuery := fmt.Sprintf(" AND event_type IN (%s)",
			// Create following part: `?,?,?,?` based on len of eventTypes.
			strings.TrimSuffix(strings.Repeat("?,", len(params.filter.eventTypes)), ","))
		qb.Append(eventsTypesInQuery,
			sliceWithTicks(params.filter.eventTypes)...,
		)
	}

	if params.order == types.EventOrderAscending {
		if params.startKeyset != nil {
			qb.Append(` AND (event_time, uid) > (?,?)`,
				fmt.Sprintf("timestamp '%s'", params.startKeyset.t.Format(athenaTimestampFormat)), fmt.Sprintf("'%s'", params.startKeyset.uid.String()))
		}

		qb.Append(` ORDER BY event_time ASC, uid ASC`)
	} else {
		if params.startKeyset != nil {
			qb.Append(` AND (event_time, uid) < (?,?)`,
				fmt.Sprintf("timestamp '%s'", params.startKeyset.t.Format(athenaTimestampFormat)), fmt.Sprintf("'%s'", params.startKeyset.uid.String()))
		}
		qb.Append(` ORDER BY event_time DESC, uid DESC`)
	}

	qb.Append(` LIMIT ?`, strconv.Itoa(params.limit))

	return qb.String(), qb.Args()
}

func (q *querier) startQueryExecution(ctx context.Context, query string, params []string) (string, error) {
	startQueryInput := &athena.StartQueryExecutionInput{
		QueryExecutionContext: &athenaTypes.QueryExecutionContext{
			Database: aws.String(q.database),
		},
		ExecutionParameters: params,
		QueryString:         aws.String(query),
	}
	if q.workgroup != "" {
		startQueryInput.WorkGroup = aws.String(q.workgroup)
	}

	if q.queryResultsS3 != "" {
		startQueryInput.ResultConfiguration = &athenaTypes.ResultConfiguration{
			OutputLocation: aws.String(q.queryResultsS3),
		}
	}

	startQueryOut, err := q.athenaCli.StartQueryExecution(ctx, startQueryInput)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return aws.ToString(startQueryOut.QueryExecutionId), nil
}

func (q *querier) waitForSuccess(ctx context.Context, queryId string) error {
	for {
		// TODO(tobiaszheller): on first call it makes sense to sleep for longer period because it's typically
		// above 1s before we can start seeing results. Come back at some point and fix it.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(q.getQueryResultsInterval):
			// continue below
		}

		resp, err := q.athenaCli.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{QueryExecutionId: aws.String(queryId)})
		if err != nil {
			return trace.Wrap(err)
		}
		state := resp.QueryExecution.Status.State
		switch state {
		case athenaTypes.QueryExecutionStateSucceeded:
			return nil
		case athenaTypes.QueryExecutionStateCancelled, athenaTypes.QueryExecutionStateFailed:
			return trace.Errorf("got unexpected state: %s", state)
		case athenaTypes.QueryExecutionStateQueued, athenaTypes.QueryExecutionStateRunning:
			continue
		default:
			return trace.Errorf("got unknown state: %s", state)
		}
	}
}

// fetchResults returns query results for given queryID.
// Athena API allows only fetch 1000 results, so if client asks for more, multiple
// calls to GetQueryResults will be necessary.
func (q *querier) fetchResults(ctx context.Context, queryId string, limit int, filter searchEventsFilter) ([]apievents.AuditEvent, string, error) {
	rb := &responseBuilder{}
	// nextToken is used as offset to next calls for GetQueryResults.
	var nextToken string
	for {
		var nextTokenPtr *string
		if nextToken != "" {
			nextTokenPtr = aws.String(nextToken)
		}
		resultResp, err := q.athenaCli.GetQueryResults(ctx, &athena.GetQueryResultsInput{
			// AWS SDK allows only 1000 results.
			MaxResults:       aws.Int32(1000),
			QueryExecutionId: aws.String(queryId),
			NextToken:        nextTokenPtr,
		})
		if err != nil {
			return nil, "", trace.Wrap(err)
		}

		sizeLimit, err := rb.appendUntilSizeLimit(resultResp, filter)
		if err != nil {
			return nil, "", trace.Wrap(err)
		}

		if sizeLimit {
			endkeySet, err := rb.endKeyset()
			if err != nil {
				return nil, "", trace.Wrap(err)
			}
			return rb.output, endkeySet.ToKey(), nil
		}

		// It means that there are no more results to fetch from athena results
		// output location.
		if resultResp.NextToken == nil {
			output := rb.output
			// We have the same amount of results as requested, return keyset
			// because there could be more results.
			if len(output) >= limit {
				endkeySet, err := rb.endKeyset()
				if err != nil {
					return nil, "", trace.Wrap(err)
				}
				return output, endkeySet.ToKey(), nil
			}
			// output is smaller then limit, no keyset needed.
			return output, "", nil
		}
		nextToken = *resultResp.NextToken

	}
}

type responseBuilder struct {
	output []apievents.AuditEvent
	// totalSize is used to track size of output
	totalSize int
}

func (r *responseBuilder) endKeyset() (*keyset, error) {
	if len(r.output) < 1 {
		// Search can returns 0 events, it means we don't have keyseyt to return
		// but it is also not an error.
		return nil, nil
	}
	lastEvent := r.output[len(r.output)-1]

	var endKeyset keyset
	var err error
	endKeyset.t = lastEvent.GetTime()
	endKeyset.uid, err = uuid.Parse(lastEvent.GetID())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &endKeyset, nil
}

// appendUntilSizeLimit converts events from json blob to apievents.AuditEvent.
// It stops if events.MaxEventBytesInResponse is reached or if there are no more
// events. It returns information if size limit was reached.
func (rb *responseBuilder) appendUntilSizeLimit(resultResp *athena.GetQueryResultsOutput, filter searchEventsFilter) (bool, error) {
	if resultResp == nil || resultResp.ResultSet == nil {
		return false, nil
	}
	for i, row := range resultResp.ResultSet.Rows {
		if len(row.Data) != 3 {
			return false, trace.BadParameter("invalid number of row at response, got %d", len(row.Data))
		}
		// GetQueryResults returns as first row header from CSV.
		// We don't need it, so we will just ignore first row if it contains
		// header.
		if i == 0 && aws.ToString(row.Data[0].VarCharValue) == "uid" {
			continue
		}
		eventData := aws.ToString(row.Data[2].VarCharValue)

		var fields events.EventFields
		if err := utils.FastUnmarshal([]byte(eventData), &fields); err != nil {
			return false, trace.Wrap(err, "failed to unmarshal event, %s", eventData)
		}
		event, err := events.FromEventFields(fields)
		if err != nil {
			return false, trace.Wrap(err)
		}
		// TODO(tobiaszheller): encode filter as query params and remove it in next PRs.
		if filter.condition != nil && !filter.condition(utils.Fields(fields)) {
			continue
		}

		if len(eventData)+rb.totalSize > events.MaxEventBytesInResponse {
			return true, nil
		}
		rb.totalSize += len(eventData)
		rb.output = append(rb.output, event)
	}
	return false, nil
}

// keyset is a point at which the searchEvents pagination ended, and can be
// resumed from.
type keyset struct {
	t   time.Time
	uid uuid.UUID
}

// FromKey attempts to parse a keyset from a string. The string is a URL-safe
// base64 encoding of the time in microseconds as an int64, the event UUID;
// numbers are encoded in little-endian.
func fromKey(key string) (*keyset, error) {
	if key == "" {
		return nil, nil
	}

	b, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(b) != 24 {
		return nil, trace.BadParameter("malformed pagination key")
	}
	ks := &keyset{}
	ks.t = time.UnixMicro(int64(binary.LittleEndian.Uint64(b[0:8]))).UTC()
	ks.uid, err = uuid.FromBytes(b[8:24])
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ks, nil
}

// ToKey converts the keyset into a URL-safe string.
func (ks *keyset) ToKey() string {
	var b [24]byte
	binary.LittleEndian.PutUint64(b[0:8], uint64(ks.t.UnixMicro()))
	copy(b[8:24], ks.uid[:])
	return base64.URLEncoding.EncodeToString(b[:])
}
