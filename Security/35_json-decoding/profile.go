package jsondecode

import (
	"bytes"
	"errors"
	"strings"
)

// User is the stored account record. IsAdmin and ID are privileged: no
// request body should ever set them.
type User struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	IsAdmin bool   `json:"isAdmin"`
}

// UpdateProfileUnsafe decodes the request body straight into the stored
// record. Every exported field is writable by the client: mass assignment
// (CWE-915), the same class as the 2012 GitHub/Rails public-key incident.
// Because v1 matches keys case-insensitively, a gateway rule that strips
// "isAdmin" does not stop "ISADMIN".
func UpdateProfileUnsafe(u *User, body []byte) error {
	return DecodeLenient(bytes.NewReader(body), u)
}

// ProfileUpdate is the input DTO for the profile endpoint. It contains only
// the fields a user may change; pointers distinguish "absent" from "empty".
type ProfileUpdate struct {
	Name  *string `json:"name"`
	Email *string `json:"email"`
}

// ErrInvalidProfile is returned when a field fails validation.
var ErrInvalidProfile = errors.New("jsondecode: invalid profile update")

// UpdateProfile decodes into ProfileUpdate with DecodeStrict, validates, and
// copies the permitted fields onto the record. A privileged field sent by the
// client is an unknown field and fails the whole request.
func UpdateProfile(u *User, body []byte) error {
	var in ProfileUpdate
	if err := DecodeStrict(body, &in); err != nil {
		return err
	}
	if in.Name != nil {
		if n := len(*in.Name); n == 0 || n > 64 {
			return ErrInvalidProfile
		}
	}
	if in.Email != nil {
		if !strings.Contains(*in.Email, "@") || len(*in.Email) > 254 {
			return ErrInvalidProfile
		}
	}
	// Validate everything before mutating anything.
	if in.Name != nil {
		u.Name = *in.Name
	}
	if in.Email != nil {
		u.Email = *in.Email
	}
	return nil
}
