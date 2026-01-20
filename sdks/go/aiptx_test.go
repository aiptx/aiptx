package aiptx

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	// Test default client creation
	client := NewClient("", "")
	if client.BaseURL != "http://localhost:8000" {
		t.Errorf("Expected default base URL, got %s", client.BaseURL)
	}

	// Test custom client creation
	client = NewClient("http://custom:9000", "test-key")
	if client.BaseURL != "http://custom:9000" {
		t.Errorf("Expected custom base URL, got %s", client.BaseURL)
	}
	if client.APIKey != "test-key" {
		t.Errorf("Expected API key to be set")
	}
}

func TestAPIError(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "Not found",
	}

	expected := "AIPTX API error (status 404): Not found"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}
