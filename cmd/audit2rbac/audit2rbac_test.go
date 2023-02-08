package main

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestEventToAttributes(t *testing.T) {
	testcases := []struct {
		name               string
		event              *audit.Event
		expectedAttributes authorizer.AttributesRecord
	}{
		{
			name: "rejected create",
			event: &audit.Event{
				Verb: "create",
				ObjectRef: &audit.ObjectReference{
					APIGroup:   "mygroup",
					APIVersion: "myversion",
					Resource:   "myresources",
					Namespace:  "mynamespace",
					// no name attribute in unauthorized create, request body is never parsed
				},
			},
			expectedAttributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{},
				Verb:            "create",
				Namespace:       "mynamespace",
				APIGroup:        "mygroup",
				APIVersion:      "myversion",
				Resource:        "myresources",
				ResourceRequest: true,
			},
		},
		{
			name: "accepted create",
			event: &audit.Event{
				Verb: "create",
				ObjectRef: &audit.ObjectReference{
					APIGroup:   "mygroup",
					APIVersion: "myversion",
					Resource:   "myresources",
					Namespace:  "mynamespace",
					Name:       "myname",
				},
			},
			expectedAttributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{},
				Verb:            "create",
				Namespace:       "mynamespace",
				APIGroup:        "mygroup",
				APIVersion:      "myversion",
				Resource:        "myresources",
				ResourceRequest: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			actualAttributes := eventToAttributes(tc.event)
			if !reflect.DeepEqual(tc.expectedAttributes, actualAttributes) {
				t.Errorf("unexpected diff:\n%s", cmp.Diff(tc.expectedAttributes, actualAttributes))
			}
		})
	}
}
