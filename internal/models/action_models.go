// internal/models/action_models.go
package models

// ActionInvocationParquetRecord defines the schema for Parquet logging of action invocations.
type ActionInvocationParquetRecord struct {
	ThingID    string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	ActionName string `parquet:"name=action_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	ActionID   string `parquet:"name=action_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Input      string `parquet:"name=input,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the input
	Timestamp  int64  `parquet:"name=timestamp,type=INT64"`                                        // Unix nanoseconds
}
