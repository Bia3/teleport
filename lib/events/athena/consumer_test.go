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
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
)

func Test_consumer_sqsMessagesCollector(t *testing.T) {
	fatalOnErrFunc := func(ctx context.Context, errC chan error) {
		err, ok := <-errC
		if ok && err != nil {
			// we don't expect error in that test case.
			t.Fatal(err)
		}
	}
	// channelClosedCondition returns function that can be used to check if eventually
	// channel was closed.
	channelClosedCondition := func(t *testing.T, ch <-chan eventAndAckID) func() bool {
		return func() bool {
			select {
			case _, ok := <-ch:
				if ok {
					t.Fatal("don't expect message here, fail")
					return false
				} else {
					// channel is closed, that's what we are waiting for.
					return true
				}
			default:
				// retry
				return false
			}
		}
	}
	log := logrus.NewEntry(logrus.New())

	maxWaitTimeOnReceiveMessagesInFake := 20 * time.Millisecond

	t.Run("scenario 1", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When 3 messages are published
		// Then 3 messages can be received from eventsChan.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		c := newSqsMessagesCollector(sqsCollectConfig{
			sqsReceiver:           fq,
			waitOnReceiveDuration: 5 * time.Millisecond,
			batchMaxItems:         20000,
		}, log, fatalOnErrFunc)
		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()
		go c.fromSQS(readSQSCtx)

		// receiver is used to read messages from eventsChan.
		r := &receiver{}
		go r.Do(eventsChan)

		// When
		fq.addEvents(
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
		)
		// Advance clock to simulate random wait time on receive messages endpoint.
		fclock.BlockUntil(maxNumberOfWorkers)
		fclock.Advance(maxWaitTimeOnReceiveMessagesInFake)

		// Then
		require.Eventually(t, func() bool {
			return len(r.GetMsgs()) == 3
		}, 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("scenario 2", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When ctx is canceled
		// Then reading chan is closed.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		c := newSqsMessagesCollector(sqsCollectConfig{
			sqsReceiver:           fq,
			waitOnReceiveDuration: 5 * time.Millisecond,
			batchMaxItems:         20000,
		}, log, fatalOnErrFunc)
		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		go c.fromSQS(readSQSCtx)

		// When
		readCancel()

		// Then
		// Make sure that channel is closed.
		require.Eventually(t, channelClosedCondition(t, eventsChan), 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("scenario 3", func(t *testing.T) {
		// Given SqsMessagesCollector reading from fake sqs with random wait time on receiveMessage call
		// When batchMaxItems is reached.
		// Then reading chan is closed.

		// Given
		fclock := clockwork.NewFakeClock()
		fq := &fakeSQS{
			clock:       fclock,
			maxWaitTime: maxWaitTimeOnReceiveMessagesInFake,
		}
		c := newSqsMessagesCollector(sqsCollectConfig{
			sqsReceiver:           fq,
			waitOnReceiveDuration: 5 * time.Millisecond,
			batchMaxItems:         3,
		}, log, fatalOnErrFunc)

		eventsChan := c.getEventsChan()

		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()

		go c.fromSQS(readSQSCtx)

		// receiver is used to read messages from eventsChan.
		r := &receiver{}
		go r.Do(eventsChan)

		// When
		fq.addEvents(
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
		)
		fclock.BlockUntil(maxNumberOfWorkers)
		fclock.Advance(maxWaitTimeOnReceiveMessagesInFake)
		require.Eventually(t, func() bool {
			t.Log(len(r.GetMsgs()))
			return assert.Len(t, r.GetMsgs(), 3)
		}, 10*time.Millisecond, 1*time.Millisecond)

		// Then
		// Make sure that channel is closed.
		require.Eventually(t, channelClosedCondition(t, eventsChan), 10*time.Millisecond, 1*time.Millisecond)
	})
}

type fakeSQS struct {
	mu          sync.Mutex
	msgs        []sqsTypes.Message
	clock       clockwork.Clock
	maxWaitTime time.Duration
}

func (f *fakeSQS) addEvents(events ...apievents.AuditEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range events {
		f.msgs = append(f.msgs, rawProtoMessage(e))
	}
}

func (f *fakeSQS) ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	// Let's use random sleep duration. That's how sqs works, you could wait up until max wait time but
	// it can return earlier.
	randSleepDuration, err := rand.Int(rand.Reader, big.NewInt(f.maxWaitTime.Nanoseconds()))
	if err != nil {
		panic(err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.clock.After(time.Duration(randSleepDuration.Int64())):
		// continue below
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) > 0 {
		out := &sqs.ReceiveMessageOutput{
			Messages: f.msgs,
		}
		f.msgs = nil
		return out, nil
	}
	return &sqs.ReceiveMessageOutput{}, nil
}

type receiver struct {
	mu   sync.Mutex
	msgs []eventAndAckID
}

func (f *receiver) Do(eventsChan <-chan eventAndAckID) {
	for e := range eventsChan {
		f.mu.Lock()
		f.msgs = append(f.msgs, e)
		f.mu.Unlock()
	}
}

func (f *receiver) GetMsgs() []eventAndAckID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.msgs
}

func rawProtoMessage(in apievents.AuditEvent) sqsTypes.Message {
	oneOf := apievents.MustToOneOf(in)
	bb, err := oneOf.Marshal()
	if err != nil {
		panic(err)
	}
	return sqsTypes.Message{
		Body: aws.String(base64.StdEncoding.EncodeToString(bb)),
		MessageAttributes: map[string]sqsTypes.MessageAttributeValue{
			payloadTypeAttr: {StringValue: aws.String(payloadTypeRawProtoEvent)},
		},
		ReceiptHandle: aws.String(uuid.NewString()),
	}
}
