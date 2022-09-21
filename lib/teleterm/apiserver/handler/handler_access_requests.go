// Copyright 2021 Gravitational, Inc
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

package handler

import (
	"context"

	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"github.com/gravitational/teleport/lib/teleterm/clusters"

	"github.com/gravitational/trace"
)

func (s *Handler) GetRequestableRoles(ctx context.Context, req *api.GetRequestableRolesRequest) (*api.GetRequestableRolesResponse, error) {
	roles, err := s.DaemonService.GetRequestableRoles(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return roles, nil
}

// GetAccessRequests returns a list of all available access requests the user can view
func (s *Handler) GetAccessRequests(ctx context.Context, req *api.GetAccessRequestsRequest) (*api.GetAccessRequestsResponse, error) {
	requests, err := s.DaemonService.GetAccessRequests(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response := &api.GetAccessRequestsResponse{}
	for _, req := range requests {
		response.Requests = append(response.Requests, newApiAccessRequest(req))
	}

	return response, nil
}

// GetAccessRequest returns a single access request by id
func (s *Handler) GetAccessRequest(ctx context.Context, req *api.GetAccessRequestsRequest) (*api.GetAccessRequestResponse, error) {
	requests, err := s.DaemonService.GetAccessRequests(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response := &api.GetAccessRequestResponse{}
	if len(requests) < 1 {
		return nil, trace.NotFound("access request %q not found", req.Id)
	}
	response.Request = newApiAccessRequest(requests[0])

	return response, nil
}

func (s *Handler) CreateAccessRequest(ctx context.Context, req *api.CreateAccessRequestRequest) (*api.CreateAccessRequestResponse, error) {
	request, err := s.DaemonService.CreateAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	createdRequest := &api.CreateAccessRequestResponse{
		Request: newApiAccessRequest(*request),
	}
	return createdRequest, nil
}

func (s *Handler) DeleteAccessRequest(ctx context.Context, req *api.DeleteAccessRequestRequest) (*api.DeleteAccessRequestResponse, error) {
	err := s.DaemonService.DeleteAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &api.DeleteAccessRequestResponse{
		Success: "true",
	}, nil
}

func (s *Handler) AssumeRole(ctx context.Context, req *api.AssumeRoleRequest) (*api.AssumeRoleResponse, error) {
	err := s.DaemonService.AssumeRole(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &api.AssumeRoleResponse{
		Success: "true",
	}, nil

}

func (s *Handler) ReviewAccessRequest(ctx context.Context, req *api.ReviewAccessRequestRequest) (*api.ReviewAccessRequestResponse, error) {
	request, err := s.DaemonService.ReviewAccessRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	response := &api.ReviewAccessRequestResponse{
		Request: newApiAccessRequest(*request),
	}
	return response, nil

}

func newApiAccessRequest(req clusters.AccessRequest) *api.AccessRequest {
	reviews := []*api.AccessRequestReview{}
	requestReviews := req.GetReviews()
	for _, rev := range requestReviews {

		reviews = append(reviews, &api.AccessRequestReview{
			Author:  rev.Author,
			Roles:   rev.Roles,
			State:   rev.ProposedState.String(),
			Reason:  rev.Reason,
			Created: rev.Created.String(),
		})
	}

	thresholdNames := make([]string, 0, len(req.GetThresholds()))
	for _, t := range req.GetThresholds() {
		if t.Name != "" {
			thresholdNames = append(thresholdNames, t.Name)
		}
	}

	requestedResourceIDs := make([]*api.ResourceID, 0, len(req.GetRequestedResourceIDs()))
	for _, r := range req.GetRequestedResourceIDs() {
		requestedResourceIDs = append(requestedResourceIDs, &api.ResourceID{
			ClusterName: r.ClusterName,
			Kind:        r.Kind,
			Name:        r.Name,
		})
	}

	return &api.AccessRequest{
		Id:                 req.GetName(),
		State:              req.GetState().String(),
		ResolveReason:      req.GetResolveReason(),
		RequestReason:      req.GetRequestReason(),
		User:               req.GetUser(),
		Roles:              req.GetRoles(),
		Created:            req.GetCreationTime().String(),
		Expires:            req.GetAccessExpiry().String(),
		Reviews:            reviews,
		SuggestedReviewers: req.GetSuggestedReviewers(),
		ThresholdNames:     thresholdNames,
		ResourceIds:        requestedResourceIDs,
	}
}
