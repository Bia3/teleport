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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func Test_querier_prepareQuery(t *testing.T) {
	const (
		tablename        = "test_table"
		selectFromPrefix = `SELECT DISTINCT uid, event_time, event_data FROM test_table`
		whereTimeRange   = ` WHERE event_date BETWEEN date(?) AND date(?) AND event_time BETWEEN ? and ?`
	)
	fromTimeUTC := time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)
	toTimeUTC := time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC)
	fromDateParam := "'2023-02-01'"
	fromTimestampParam := "timestamp '2023-02-01 00:00:00'"
	toDateParam := "'2023-03-01'"
	toTimestampParam := "timestamp '2023-03-01 00:00:00'"
	timeRangeParams := []string{fromDateParam, toDateParam, fromTimestampParam, toTimestampParam}

	otherTimeUTC := time.Date(2023, 2, 15, 0, 0, 0, 0, time.UTC)
	otherTimestampParam := "timestamp '2023-02-15 00:00:00'"

	tests := []struct {
		name         string
		searchParams searchParams
		wantQuery    string
		wantParams   []string
	}{
		{
			name: "query on time range",
			searchParams: searchParams{
				fromUTC: fromTimeUTC,
				toUTC:   toTimeUTC,
				limit:   100,
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` ORDER BY event_time ASC, uid ASC LIMIT ?`,
			wantParams: append(timeRangeParams, "100"),
		},
		{
			name: "query on time range order DESC",
			searchParams: searchParams{
				fromUTC: fromTimeUTC,
				toUTC:   toTimeUTC,
				limit:   100,
				order:   types.EventOrderDescending,
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` ORDER BY event_time DESC, uid DESC LIMIT ?`,
			wantParams: append(timeRangeParams, "100"),
		},
		{
			name: "query with event types",
			searchParams: searchParams{
				fromUTC: fromTimeUTC,
				toUTC:   toTimeUTC,
				filter:  searchEventsFilter{eventTypes: []string{"app.create", "app.delete"}},
				limit:   100,
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` AND event_type IN (?,?) ORDER BY event_time ASC, uid ASC LIMIT ?`,
			wantParams: append(timeRangeParams, "'app.create'", "'app.delete'", "100"),
		},
		{
			name: "session id",
			searchParams: searchParams{
				fromUTC:   fromTimeUTC,
				toUTC:     toTimeUTC,
				sessionID: "9762a4fe-ac4b-47b5-ba4f-5f70d065849a",
				limit:     100,
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` AND session_id = ? ORDER BY event_time ASC, uid ASC LIMIT ?`,
			wantParams: append(timeRangeParams, "'9762a4fe-ac4b-47b5-ba4f-5f70d065849a'", "100"),
		},
		{
			name: "query on time range with keyset",
			searchParams: searchParams{
				fromUTC: fromTimeUTC,
				toUTC:   toTimeUTC,
				limit:   100,
				startKeyset: &keyset{
					t:   otherTimeUTC,
					uid: uuid.MustParse("9762a4fe-ac4b-47b5-ba4f-5f70d065849a"),
				},
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` AND (event_time, uid) > (?,?) ORDER BY event_time ASC, uid ASC LIMIT ?`,
			wantParams: append(timeRangeParams, otherTimestampParam, "'9762a4fe-ac4b-47b5-ba4f-5f70d065849a'", "100"),
		},
		{
			name: "query on time range DESC with keyset",
			searchParams: searchParams{
				fromUTC: fromTimeUTC,
				toUTC:   toTimeUTC,
				limit:   100,
				order:   types.EventOrderDescending,
				startKeyset: &keyset{
					t:   otherTimeUTC,
					uid: uuid.MustParse("9762a4fe-ac4b-47b5-ba4f-5f70d065849a"),
				},
			},
			wantQuery: selectFromPrefix + whereTimeRange +
				` AND (event_time, uid) < (?,?) ORDER BY event_time DESC, uid DESC LIMIT ?`,
			wantParams: append(timeRangeParams, otherTimestampParam, "'9762a4fe-ac4b-47b5-ba4f-5f70d065849a'", "100"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotQuery, gotParams := prepareQuery(tt.searchParams, tablename)
			require.Empty(t, cmp.Diff(gotQuery, tt.wantQuery), "query")
			require.Empty(t, cmp.Diff(gotParams, tt.wantParams), "params")
		})
	}
}

func Test_keyset(t *testing.T) {
	ts := time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)
	uid := uuid.MustParse("9762a4fe-ac4b-47b5-ba4f-5f70d065849a")
	ks := &keyset{
		t:   ts,
		uid: uid,
	}
	key := ks.ToKey()

	fromKs, err := fromKey(key)
	require.NoError(t, err)
	require.Equal(t, ks, fromKs)
}
