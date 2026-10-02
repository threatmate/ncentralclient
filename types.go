package ncentralclient

import (
	"encoding/json"
	"fmt"
	"time"
)

type GenericResult[T any] struct {
	Data  T `json:"data"`
	Links struct {
	} `json:"_links"`
	Warning any `json:"_warning"`
}

type GenericPage[T any] struct {
	Data       []T `json:"data"`
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
	ItemCount  int `json:"itemCount"`
	TotalItems int `json:"totalItems"`
	TotalPages int `json:"totalPages"`
	Links      struct {
		FirstPage    *string `json:"firstPage"`
		PreviousPage *string `json:"previousPage"`
		NextPage     *string `json:"nextPage"`
		LastPage     *string `json:"lastPage"`
	} `json:"_links"`
	Warning any `json:"_warning"`
}

var DateTimeFormats = []string{
	"2006-01-02T15:04:05.999",
	"2006-01-02T15:04:05.999-07:00",
	// UTC with a trailing "Z", which "-07:00" does not accept. N-central sends
	// some device timestamps this way, and one such device fails the whole
	// device list.
	"2006-01-02T15:04:05.999Z07:00",
}

type DateTime time.Time

func (d *DateTime) UnmarshalJSON(b []byte) error {
	var stringValue string
	if err := json.Unmarshal(b, &stringValue); err != nil {
		return err
	}
	for _, format := range DateTimeFormats {
		timeValue, err := time.Parse(format, stringValue)
		if err == nil {
			*d = DateTime(timeValue)
			return nil
		}
	}
	return fmt.Errorf("could not parse as date time using %d formats: %s", len(DateTimeFormats), stringValue)
}

func (d DateTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(d).Format(DateTimeFormats[0]))
}
