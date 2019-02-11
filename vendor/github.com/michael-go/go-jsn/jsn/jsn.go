package jsn

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Map map[string]interface{}

// TODO: how to handle error? ..
func (m Map) Json() Json {
	j, _ := NewJson(m)
	return j
}

func (m Map) Raw() map[string]interface{} {
	return map[string]interface{}(m)
}

func (m Map) Marshal() (string, error) {
	buf, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(buf), err
}

func (m Map) MarshalIndent(prefix, indent string) (string, error) {
	buf, err := json.MarshalIndent(m, prefix, indent)
	if err != nil {
		return "", err
	}
	return string(buf), err
}

func (m Map) Pretty() string {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return ""
	}

	return string(buf)
}

func (m Map) Stringify() string {
	buf, err := json.Marshal(m)
	if err != nil {
		return ""
	}

	return string(buf)
}

func (m Map) StringifyIndent(prefix, indent string) string {
	buf, err := json.MarshalIndent(m, prefix, indent)
	if err != nil {
		return ""
	}

	return string(buf)
}

//////////////////

type String struct {
	Value   string
	IsValid bool
}

type Int struct {
	Value   int
	IsValid bool
}

type Int64 struct {
	Value   int64
	IsValid bool
}

type Float64 struct {
	Value   float64
	IsValid bool
}

type Bool struct {
	Value   bool
	IsValid bool
}

type Array struct {
	elements []interface{}
	IsValid  bool
}

func (a Array) Elements() []Json {
	if !a.IsValid || a.elements == nil {
		return []Json{}
	}

	values := make([]Json, len(a.elements))
	for i := 0; i < len(a.elements); i++ {
		values[i] = Json{a.elements[i], true}
	}

	return values
}

/////////////////

type Json struct {
	data   interface{}
	exists bool
}

func NewJson(src interface{}) (js Json, err error) {
	var data interface{}

	switch src.(type) {
	case []byte:
		err = json.Unmarshal(src.([]byte), &data)
	case string:
		err = json.Unmarshal([]byte(src.(string)), &data)
	case io.Reader:
		err = json.NewDecoder(src.(io.Reader)).Decode(&data)
	default:
		var bytes []byte
		bytes, err = json.Marshal(src)
		if err != nil {
			break
		}

		err = json.Unmarshal(bytes, &data)
	}

	if err == nil {
		js = Json{data, true}
	}

	return
}

func (j Json) asMap() (m map[string]interface{}, ok bool) {
	if !j.exists {
		return nil, false
	}

	switch j.data.(type) {
	case map[string]interface{}:
		return j.data.(map[string]interface{}), true
	default:
		return nil, false
	}
}

func (j Json) asArray() (a []interface{}, ok bool) {
	if !j.exists {
		return nil, false
	}

	a, ok = j.data.([]interface{})
	return
}

func (j Json) Exists(key string) bool {
	m, ok := j.asMap()

	if !ok {
		return false
	}

	_, exists := m[key]
	return exists
}

func (j Json) Get(key string) Json {
	m, ok := j.asMap()

	if !ok {
		return Json{}
	}

	v, exists := m[key]
	return Json{v, exists}
}

func (j Json) K(key string) Json {
	return j.Get(key)
}

func (j Json) I(index int) Json {
	a, ok := j.asArray()

	if !ok {
		return Json{}
	}

	if index < 0 || index > len(a)-1 {
		return Json{}
	}

	return Json{a[index], true}
}

// IterMap calls the callback for every kay-value pair in a JSON map,
// and returns the number of keys iterated.
// If it's not a map value, this method will do nothing.
// Caller can break the loop by returning false from the callback.
func (j Json) IterMap(f func(key string, value Json) bool) int {
	m, ok := j.asMap()
	if !ok {
		return 0
	}

	count := 0
	for k, v := range m {
		count += 1
		if !f(k, Json{v, true}) {
			break
		}
	}

	return count
}

func (j Json) Undefined() bool {
	return !j.exists
}

func (j Json) Null() bool {
	return j.exists && j.data == nil
}

func (j Json) NullOrUndefined() bool {
	return j.data == nil
}

func (j Json) String() String {
	if !j.exists {
		return String{}
	}

	if s, ok := (j.data).(string); ok {
		return String{s, true}
	}
	return String{}
}

func (j Json) Int64() Int64 {
	if !j.exists {
		return Int64{}
	}

	switch j.data.(type) {
	case float64:
		return Int64{int64(j.data.(float64)), true}
	case json.Number:
		v, err := j.data.(json.Number).Int64()
		return Int64{v, err == nil}
	default:
		return Int64{}
	}
}

func (j Json) Int() Int {
	v := j.Int64()

	return Int{int(v.Value), v.IsValid}
}

func (j Json) Float64() Float64 {
	if !j.exists {
		return Float64{}
	}

	switch j.data.(type) {
	case float64:
		return Float64{j.data.(float64), true}
	case json.Number:
		v, err := j.data.(json.Number).Float64()
		return Float64{v, err == nil}
	default:
		return Float64{}
	}
}

func (j Json) Bool() Bool {
	if !j.exists {
		return Bool{}
	}

	switch j.data.(type) {
	case bool:
		return Bool{j.data.(bool), true}
	default:
		return Bool{}
	}
}

func (j Json) Array() Array {
	a, ok := j.asArray()

	return Array{a, ok}
}

func (j Json) Raw() interface{} {
	return j.data
}

func (j Json) Unmarshal(target interface{}) error {
	var data interface{}
	if j.exists {
		data = j.data
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, target)
}

func (j Json) Marshal() (string, error) {
	buf, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	return string(buf), err
}

func (j Json) MarshalIndent(prefix, indent string) (string, error) {
	buf, err := json.MarshalIndent(j, prefix, indent)
	if err != nil {
		return "", err
	}
	return string(buf), err
}

func (j Json) Pretty() string {
	buf, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return ""
	}

	return string(buf)
}

func (j Json) StringifyIndent(prefix, indent string) string {
	buf, err := json.MarshalIndent(j, prefix, indent)
	if err != nil {
		return ""
	}

	return string(buf)
}

func (j Json) Stringify() string {
	buf, err := json.Marshal(j)
	if err != nil {
		return ""
	}

	return string(buf)
}

// implementing json.Marshaler interface
func (j Json) MarshalJSON() ([]byte, error) {
	if j.exists {
		return json.Marshal(j.data)
	} else {
		return json.Marshal(Json{}.data)
	}
}

// implementing the json.Unmarshler interface
func (j *Json) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &j.data)

	j.exists = (err == nil)
	return err
}

// implementing the sql.Scanner interface
func (j *Json) Scan(src interface{}) error {
	switch src.(type) {
	case []byte:
		return j.UnmarshalJSON(src.([]byte))
	default:
		return fmt.Errorf("unsupprted src type")
	}
}

// implementing the sql/driver.Valuer interface
func (j Json) Value() (driver.Value, error) {
	bytes, err := j.MarshalJSON()
	return driver.Value(bytes), err
}

func (j Json) Reader() io.Reader {
	//TODO: is ignoring the error here is ok?
	bytes, _ := json.Marshal(j)

	return strings.NewReader(string(bytes))
}
