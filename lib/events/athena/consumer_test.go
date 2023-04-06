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
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
)

func Test_consumer_msgsFromQueue(t *testing.T) {
	fq := &fakeSQS{}
	c := &sqsMessagesCollector{
		log: logrus.NewEntry(logrus.New()),
		config: sqsCollectConfig{
			sqsReceiver:           fq,
			waitOnReceiveDuration: 5 * time.Millisecond,
			batchMaxItems:         20000,
		},
		errHandlingFn: func(ctx context.Context, errC chan error) {
			err, ok := <-errC
			if ok && err != nil {
				// we don't expect error in that test case.
				t.Fatal(err)
			}
		},
	}

	t.Run("publish 3 events via fake and expect it on receive channel", func(t *testing.T) {
		fq.clear()
		eventsChan := make(chan eventAndAckID, 100)
		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()
		go c.msgsFromQueue(readSQSCtx, eventsChan)

		r := &receiver{}
		go r.Do(eventsChan)

		fq.addEvents(
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
		)
		time.Sleep(25 * time.Millisecond)
		require.Len(t, r.GetMsgs(), 3)

		// Make sure that after canceling context, no more events are returned - so it should still be 3.
		readCancel()
		time.Sleep(5 * time.Millisecond)
		fq.addEvents(&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}})
		time.Sleep(25 * time.Millisecond)
		require.Len(t, r.GetMsgs(), 3)
	})
	t.Run("verify that if maxBatchSize is reached, msgsFromQueue returns", func(t *testing.T) {
		fq.clear()
		eventsChan := make(chan eventAndAckID, 100)
		readSQSCtx, readCancel := context.WithCancel(context.Background())
		defer readCancel()
		c.config.batchMaxItems = 3
		go c.msgsFromQueue(readSQSCtx, eventsChan)

		r := &receiver{}
		go r.Do(eventsChan)

		fq.addEvents(
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
			&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}},
		)
		time.Sleep(25 * time.Millisecond)
		require.Len(t, r.GetMsgs(), 3)
		// verify that adding next won't be receive, because maxSize is reached.
		fq.addEvents(&apievents.AppCreate{Metadata: apievents.Metadata{Type: events.AppCreateEvent}})
		time.Sleep(25 * time.Millisecond)
		require.Len(t, r.GetMsgs(), 3)
	})
}

type fakeSQS struct {
	mu   sync.Mutex
	msgs []sqsTypes.Message
}

func (f *fakeSQS) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = nil
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
	randSleepDuration, err := rand.Int(rand.Reader, big.NewInt(20*time.Millisecond.Nanoseconds()))
	if err != nil {
		panic(err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Duration(randSleepDuration.Int64())):
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
