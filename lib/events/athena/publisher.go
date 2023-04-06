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
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snsTypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"

	apievents "github.com/gravitational/teleport/api/types/events"
)

const (
	payloadTypeAttr          = "payload_type"
	payloadTypeRawProtoEvent = "raw_proto_event"
	payloadTypeS3Based       = "s3_based_payload"

	// maxSNSMessageSize defines maximum size of SNS message. AWS allows 256KB
	// however it counts also headers. We round it to 250KB, just to be sure.
	maxSNSMessageSize = 250 * 1024
	// maxS3BasedSize defines some resonable threshold for S3 based messages (2GB).
	maxS3BasedSize = 2 * 1024 * 1024 * 1024
)

// publisher is a SNS based events publisher.
// It publishes proto events directly to SNS topic, or use S3 bucket
// if payload is too large for SNS.
type publisher struct {
	topicARN      string
	snsPublisher  snsPublisher
	uploader      s3uploader
	payloadBucket string
	payloadPrefix string
}

type snsPublisher interface {
	Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

type s3uploader interface {
	Upload(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error)
}

// newPublisher returns new instance of publisher.
func newPublisher(cfg Config, awsCfg aws.Config, log *log.Entry) *publisher {
	r := retry.NewStandard(func(so *retry.StandardOptions) {
		so.MaxAttempts = 20
		so.MaxBackoff = 1 * time.Minute
	})

	// TODO(tobiaszheller): consider reworking lib/observability to work also on s3 sdk-v2.
	return &publisher{
		topicARN: cfg.TopicARN,
		snsPublisher: sns.NewFromConfig(awsCfg, func(o *sns.Options) {
			o.Retryer = r
		}),
		uploader:      manager.NewUploader(s3.NewFromConfig(awsCfg)),
		payloadBucket: cfg.largeEventsBucket,
		payloadPrefix: cfg.largeEventsPrefix,
	}
}

// EmitAuditEvent emits audit event.
func (p *publisher) EmitAuditEvent(ctx context.Context, in apievents.AuditEvent) error {
	// Just double check that audit event has minimum necessary fields for athena
	// to works. Teleport emitter layer above makes sure that they are filled.
	if in.GetID() == "" {
		return trace.BadParameter("missing uid of audit event %s", in.GetType())
	}
	if in.GetTime().IsZero() {
		return trace.BadParameter("missing time of audit event %s", in.GetType())
	}

	oneOf, err := apievents.ToOneOf(in)
	if err != nil {
		return trace.Wrap(err)
	}
	marshaledProto, err := oneOf.Marshal()
	if err != nil {
		return trace.Wrap(err)
	}

	b64Encoded := base64.StdEncoding.EncodeToString(marshaledProto)
	if len(b64Encoded) > maxSNSMessageSize {
		if len(b64Encoded) > maxS3BasedSize {
			return trace.BadParameter("message too large to publish, size %d", len(b64Encoded))
		}
		return trace.Wrap(p.emitViaS3(ctx, in.GetID(), marshaledProto))
	}
	return trace.Wrap(p.emitViaSNS(ctx, in.GetID(), b64Encoded))
}

func (p *publisher) emitViaS3(ctx context.Context, uid string, marshaledEvent []byte) error {
	path := filepath.Join(p.payloadPrefix, uid)
	out, err := p.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(p.payloadBucket),
		Key:    aws.String(path),
		Body:   bytes.NewBuffer(marshaledEvent),
	})
	if err != nil {
		return trace.Wrap(err)
	}

	var versionID string
	if out.VersionID != nil {
		versionID = *out.VersionID
	}
	msg := &apievents.AthenaS3EventPayload{
		Path:      path,
		VersionId: versionID,
	}
	buf, err := msg.Marshal()
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = p.snsPublisher.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(p.topicARN),
		Message:  aws.String(string(buf)),
		MessageAttributes: map[string]snsTypes.MessageAttributeValue{
			payloadTypeAttr: {DataType: aws.String("String"), StringValue: aws.String(payloadTypeS3Based)},
		},
	})
	return trace.Wrap(err)
}

func (p *publisher) emitViaSNS(ctx context.Context, uid string, b64Encoded string) error {
	_, err := p.snsPublisher.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(p.topicARN),
		Message:  aws.String(b64Encoded),
		MessageAttributes: map[string]snsTypes.MessageAttributeValue{
			payloadTypeAttr: {DataType: aws.String("String"), StringValue: aws.String(payloadTypeRawProtoEvent)},
		},
	})
	return trace.Wrap(err)
}
