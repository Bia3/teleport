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
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	// maxWaitTimeOnReceiveMessageFromSQS defines how long single
	// receiveFromQueue will wait if there is no max events (10).
	maxWaitTimeOnReceiveMessageFromSQS = 5 * time.Second
	// maxNumberOfWorkers defines how many workers are processing messages
	// from queue or writing parquet files to s3.
	maxNumberOfWorkers = 5
	// maxNumberOfMessagesFromReceive defines how many messages single receive
	// call can return. Maximum value is 10.
	// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
	maxNumberOfMessagesFromReceive = 10
)

// consumer is responsible for receiving messages from SQS, batching them up to
// certain size or interval, and writes to s3 as parquet file.
type consumer struct {
	*log.Entry
	sqsReceiver         sqsReceiver
	backend             backend.Backend
	storeLocationPrefix string
	storeLocationBucket string
	batchMaxItems       int
	batchMaxInterval    time.Duration

	collectConfig sqsCollectConfig
}

type sqsCollectConfig struct {
	sqsReceiver       sqsReceiver
	queueURL          string
	payloadBucket     string
	payloadDownloader s3downloader
	// visibilityTimeout defines how long message won't be available for other
	// receiveMessage calls. If timeout happens, and message was not deleted
	// it will return to the queue.
	visibilityTimeout     int32
	waitOnReceiveTimeout  int32
	waitOnReceiveDuration time.Duration

	batchMaxItems int
}

type sqsReceiver interface {
	ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
}

type s3downloader interface {
	Download(ctx context.Context, w io.WriterAt, input *s3.GetObjectInput, options ...func(*manager.Downloader)) (n int64, err error)
}

func newConsumer(cfg Config, awsCfg aws.Config, backend backend.Backend, logEntry *log.Entry) (*consumer, error) {
	// TODO(tobiaszheller): move this to Config.CheckAndSetDefaults.
	u, err := url.Parse(cfg.LocationS3)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	largeEventsURL, err := url.Parse(cfg.LargeEventsS3)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s3cli := s3.NewFromConfig(awsCfg)
	sqsCli := sqs.NewFromConfig(awsCfg)
	return &consumer{
		Entry:               logEntry,
		sqsReceiver:         sqsCli,
		backend:             backend,
		storeLocationPrefix: strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/"),
		storeLocationBucket: u.Host,
		batchMaxItems:       cfg.BatchMaxItems,
		batchMaxInterval:    cfg.BatchMaxInterval,
		collectConfig: sqsCollectConfig{
			sqsReceiver: sqsCli,
			queueURL:    cfg.QueueURL,
			// TODO(tobiaszheller): use s3 manager from teleport observability.
			payloadDownloader:     manager.NewDownloader(s3cli),
			payloadBucket:         largeEventsURL.Host,
			visibilityTimeout:     int32(cfg.BatchMaxInterval.Seconds()),
			waitOnReceiveTimeout:  int32(maxWaitTimeOnReceiveMessageFromSQS.Seconds()),
			waitOnReceiveDuration: maxWaitTimeOnReceiveMessageFromSQS,
			batchMaxItems:         cfg.BatchMaxItems,
		},
	}, nil
}

// run continuously runs batching job. It is blocking operation.
// It is stopped via canceling context.
func (c *consumer) run(ctx context.Context) {
	const lockName = "athena_batcher"
	// lockTTL is time after which other auth server can acquire lock.
	// It can be half of BatchMaxInterval because RunWhileLocked automatically
	// refresh TTL if job is still running.
	lockTTL := c.batchMaxInterval / 2
	var err error
	for {
		// TODO(tobiaszheller): come back at some point and rework configuration of runWhileLocked.
		// Now it tries every 250ms to acquire lock which can cause pressure on backend.
		err = backend.RunWhileLocked(ctx, c.backend, lockName, lockTTL, func(ctx context.Context) error {
			return trace.Wrap(c.singleBatch(ctx))
		})
		if err != nil {
			// Ctx.Cancel is used to stop batcher
			if ctx.Err() != nil {
				c.Debug("Batcher has been stopped")
				return
			}
			c.Errorf("Batcher single run failed: %v", err)
		}
	}
}

// singleBatch creates single batch of events. It waits either up to BatchMaxInterval
// or BatchMaxItems while reading events from queue. Batch is sent to s3 as
// parquet file and at the end events are deleted from queue.
func (c *consumer) singleBatch(ctx context.Context) error {
	start := time.Now()
	var size int
	// TODO(tobiaszheller): we need some metrics to track it.
	defer func() {
		c.Debugf("Batch of %d took: %s", size, time.Since(start))
	}()

	msgsCollector := newSqsMessagesCollector(c.collectConfig, c.Entry, func(ctx context.Context, errC chan error) {
		err := trace.NewAggregateFromChannel(errC, ctx)
		if err != nil {
			c.Entry.WithError(err).Error("Failure processing SQS messages")
		}
	})

	// eventsChan is used for communication between [fromSQS] and [writeToS3].
	eventsChan := msgsCollector.getEventsChan()

	readSQSCtx, readCancel := context.WithTimeout(ctx, c.batchMaxInterval)
	defer readCancel()

	go func() {
		msgsCollector.fromSQS(readSQSCtx)
	}()
	var err error
	size, err = c.writeToS3(ctx, eventsChan)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
	// TODO(tobiaszheller): delete messages from queue in next PR.
}

// sqsMessagesCollector is responsible for collecting messages from SQS and
// writing to on channel.
type sqsMessagesCollector struct {
	log           *log.Entry
	config        sqsCollectConfig
	errHandlingFn func(ctx context.Context, errC chan error)
	eventsChan    chan eventAndAckID
}

// newSqsMessagesCollector returns message collector.
// Collector sends collected messages from SQS on events channel.
func newSqsMessagesCollector(cfg sqsCollectConfig, log *log.Entry, errHandlingFn func(ctx context.Context, errC chan error)) *sqsMessagesCollector {
	return &sqsMessagesCollector{
		log:           log,
		config:        cfg,
		errHandlingFn: errHandlingFn,
		eventsChan:    make(chan eventAndAckID, cfg.batchMaxItems),
	}
}

// getEventsChan returns channel which can be used to read messages from SQS.
// When collector finishes, channel will be closed.
func (s *sqsMessagesCollector) getEventsChan() <-chan eventAndAckID {
	return s.eventsChan
}

// fromSQS receives messages from SQS and sends it on eventsC channel.
// It runs until context is canceled (via timeout) or when maxItems is reached.
// MaxItems is soft limit and can happen that it will return more items then MaxItems.
func (s *sqsMessagesCollector) fromSQS(ctx context.Context) {
	// Errors should be immediately process by error handling loop, so 10 size
	// should be enough to not cause blocking.
	errorsC := make(chan error, 10)
	defer close(errorsC)

	// errhandle loop for receiving single event errors.
	go func() {
		s.errHandlingFn(ctx, errorsC)
	}()
	eventsC := s.eventsChan

	count := 0
	countMu := sync.Mutex{}

	// wokerCtx is mechanism to stop other workers when maxItems is reached.
	wokerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(maxNumberOfWorkers)
	for i := 0; i < maxNumberOfWorkers; i++ {
		go func(i int) {
			defer wg.Done()
			for {
				if wokerCtx.Err() != nil {
					return
				}

				// If there is not enough time to process receiveMessage call
				// we can return immediately. It's added because if
				// receiveMessages is canceled message is marked as not
				// processed after VisibilitTimeout (equal to BatchInterval).
				if deadline, ok := wokerCtx.Deadline(); ok && time.Until(deadline) <= s.config.waitOnReceiveDuration {
					return
				}
				events, err := s.receiveMessages(wokerCtx)
				if err != nil {
					// TODO(tobiaszheller): maybe we need to check for other errors than cancel as well
					// from aws SDK.
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return
					}
					errorsC <- trace.Wrap(err)
				}
				for _, e := range events {
					if e.err != nil {
						errorsC <- e.err
						continue
					}
					eventsC <- eventAndAckID{
						event:         e.data,
						receiptHandle: e.receiptHandle,
					}
				}

				countMu.Lock()
				count += len(events)
				if count >= s.config.batchMaxItems {
					countMu.Unlock()
					cancel()
					return
				}
				countMu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	close(eventsC)
}

type sqsMessageWithError struct {
	// receiptHandle is used to delete message from queue
	receiptHandle string
	data          *eventParquet
	err           error
}

func (s *sqsMessagesCollector) receiveMessages(ctx context.Context) ([]sqsMessageWithError, error) {
	out := make([]sqsMessageWithError, 0, 10)
	sqsOut, err := s.config.sqsReceiver.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:              aws.String(s.config.queueURL),
		MaxNumberOfMessages:   maxNumberOfMessagesFromReceive,
		WaitTimeSeconds:       s.config.waitOnReceiveTimeout,
		VisibilityTimeout:     s.config.visibilityTimeout,
		MessageAttributeNames: []string{payloadTypeAttr},
	})
	if err != nil {
		return nil, err
	}
	if len(sqsOut.Messages) < 1 {
		return out, nil
	}
	for _, msg := range sqsOut.Messages {
		event, err := s.convertSingleMessage(ctx, msg)
		if err != nil {
			out = append(out, sqsMessageWithError{
				err: trace.Wrap(err),
			})
			continue
		}
		out = append(out, sqsMessageWithError{
			receiptHandle: *msg.ReceiptHandle,
			data:          event,
		})
	}
	return out, nil
}

func (s *sqsMessagesCollector) convertSingleMessage(ctx context.Context, msg sqsTypes.Message) (*eventParquet, error) {
	payloadType, err := validateSQSMessage(msg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var protoMarshaledOneOf []byte
	switch payloadType {
	// default case is hanlded in validateSQSMessage.
	case payloadTypeS3Based:
		protoMarshaledOneOf, err = s.downloadEventFromS3(ctx, *msg.Body)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// continue below
	case payloadTypeRawProtoEvent:
		protoMarshaledOneOf, err = base64.StdEncoding.DecodeString(*msg.Body)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// continue below
	}

	oneOf := apievents.OneOf{}
	err = oneOf.Unmarshal(protoMarshaledOneOf)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	event, err := apievents.FromOneOf(oneOf)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	jsonBlob, err := utils.FastMarshal(event)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &eventParquet{
		EventType: event.GetType(),
		EventTime: event.GetTime().UnixMilli(),
		UID:       event.GetID(),
		SessionID: events.GetSessionID(event),
		EventData: string(jsonBlob),
	}, nil
}

func validateSQSMessage(msg sqsTypes.Message) (string, error) {
	if msg.Body == nil || msg.MessageAttributes == nil {
		// This should not happen. If it happen though, it will be retried
		// and go to dead-letter queue after max attempts.
		return "", trace.BadParameter("missing Body or MessageAttributes of msg: %v", msg)
	}
	if msg.ReceiptHandle == nil {
		return "", trace.BadParameter("missing ReceiptHandle")
	}
	v := msg.MessageAttributes[payloadTypeAttr]
	if v.StringValue == nil {
		// This should not happen. If it happen though, it will be retried
		// and go to dead-letter queue after max attempts.
		return "", trace.BadParameter("message without %q attribute", payloadTypeAttr)
	}
	payloadType := *v.StringValue
	if !slices.Contains([]string{payloadTypeRawProtoEvent, payloadTypeS3Based}, payloadType) {
		return "", trace.BadParameter("unsupported payload type %s", payloadType)
	}
	return payloadType, nil
}

type eventAndAckID struct {
	event         *eventParquet
	receiptHandle string
}

func (s *sqsMessagesCollector) downloadEventFromS3(ctx context.Context, payload string) ([]byte, error) {
	// TODO(tobiaszheller): parse payload from proto. Waiting for other with proto.
	path := payload
	versionID := ""

	s.log.Debugf("Downloading %v %v [%v].", s.config.payloadBucket, path, versionID)

	buf := manager.NewWriteAtBuffer([]byte{})
	written, err := s.config.payloadDownloader.Download(ctx, buf, &s3.GetObjectInput{
		Bucket:    aws.String(s.config.payloadBucket),
		Key:       aws.String(path),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, ConvertS3Error(err)
	}
	if written == 0 {
		return nil, trace.NotFound("payload for %v is not found", path)
	}
	return buf.Bytes(), nil
}

// ConvertS3Error wraps S3 error and returns trace equivalent
func ConvertS3Error(err error, args ...interface{}) error {
	if err == nil {
		return nil
	}
	var nsk *s3Types.NoSuchKey
	if errors.As(err, &nsk) {
		return trace.NotFound(nsk.Error(), args...)
	}
	var nsb *s3Types.NoSuchBucket
	if errors.As(err, &nsb) {
		return trace.NotFound(nsb.Error(), args...)
	}
	var nsu *s3Types.NoSuchUpload
	if errors.As(err, &nsu) {
		return trace.NotFound(nsu.Error(), args...)
	}
	return err
}

// writeToS3 is not doing anything then just receiving from channel and printing
// for now. It will be changed in next PRs to actually write to S3 via parquet writer.
func (c *consumer) writeToS3(ctx context.Context, eventsChan <-chan eventAndAckID) (int, error) {
	var size int
	for {
		select {
		case <-ctx.Done():
			return size, trace.Wrap(ctx.Err())
		case eventAndAckID, ok := <-eventsChan:
			if !ok {
				return size, nil
			}
			size++
			c.Debugf("Received event: %s %s", eventAndAckID.event.UID, eventAndAckID.event.EventType)
		}
	}
}
