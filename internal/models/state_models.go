package models

// PropertyStateParquetRecord defines the schema for Parquet logging of property states.
type PropertyStateParquetRecord struct {
	ThingID      string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	PropertyName string `parquet:"name=property_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Value        string `parquet:"name=value,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the value
	Timestamp    int64  `parquet:"name=timestamp,type=INT64"`                                        // Unix nanoseconds
	Source       string `parquet:"name=source,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
}
