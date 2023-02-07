/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import "github.com/gravitational/teleport/api/types"

// MarshalFunc is a type signature for a marshaling function.
type MarshalFunc[T types.Resource] func(T, ...MarshalOption) ([]byte, error)

// UnmarshalFunc is a type signature for an unmarshaling function.
type UnmarshalFunc[T types.Resource] func([]byte, ...MarshalOption) (T, error)
