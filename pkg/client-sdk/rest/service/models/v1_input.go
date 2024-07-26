// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// V1Input v1 input
// swagger:model v1Input
type V1Input struct {

	// txid
	Txid string `json:"txid,omitempty"`

	// vout
	Vout int64 `json:"vout,omitempty"`
}

// Validate validates this v1 input
func (m *V1Input) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1Input) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1Input) UnmarshalBinary(b []byte) error {
	var res V1Input
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}