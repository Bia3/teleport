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

import "time"

type eventParquet struct {
	EventType string `parquet:"name=event_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	EventTime int64  `parquet:"name=event_time, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	UID       string `parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	SessionID string `parquet:"name=session_id, type=BYTE_ARRAY, convertedtype=UTF8"`
	EventData string `parquet:"name=event_data, type=BYTE_ARRAY, convertedtype=UTF8"`
}

func (e eventParquet) GetDate() string {
	return time.UnixMilli(e.EventTime).Format("2006-01-02")
}
