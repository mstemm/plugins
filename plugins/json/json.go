///////////////////////////////////////////////////////////////////////////////
// This plugin is a general json parser. It can be used to extract arbitrary
// fields from a buffer containing json data.
///////////////////////////////////////////////////////////////////////////////
package main

/*
#include <stdlib.h>
#include <inttypes.h>
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"unsafe"

	"github.com/mstemm/libsinsp-plugin-sdk-go/pkg/sinsp"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginRequiredApiVersion = "1.0.0"
	PluginName               = "json"
	PluginDescription        = "implements extracting arbitrary fields from inputs formatted as JSON"
	PluginContact            = "github.com/leogr/plugins/"
	PluginVersion = "0.0.1"
)

const verbose bool = false
const outBufSize uint32 = 65535

type pluginContext struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastError   error
}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginRequiredApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	return sinsp.TypeExtractorPlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	if !verbose {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	// Allocate the container for buffers and context
	pluginState := sinsp.NewStateContainer()

	// Allocate the context struct and set it to the state
	pCtx := &pluginContext{}
	sinsp.SetContext(pluginState, unsafe.Pointer(pCtx))

	*rc = sinsp.ScapSuccess
	return pluginState
}

//export plugin_get_last_error
func plugin_get_last_error(plgState unsafe.Pointer) *C.char {
	pCtx := (*pluginContext)(sinsp.Context(plgState))
	if pCtx.lastError != nil {
		return C.CString(pCtx.lastError.Error())
	}

	return C.CString("no error")
}

//export plugin_destroy
func plugin_destroy(plgState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)
	sinsp.Free(plgState)
}

//export plugin_get_name
func plugin_get_name() *C.char {
	return C.CString(PluginName)
}

//export plugin_get_version
func plugin_get_version() *C.char {
	return C.CString(PluginVersion)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	return C.CString(PluginDescription)
}

//export plugin_get_contact
func plugin_get_contact() *C.char {
	return C.CString(PluginContact)
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	flds := []sinsp.FieldEntry{
		{Type: "string", Name: "json.value", ArgRequired: true, Desc: "allows to extract a value from a JSON-encoded input. Syntax is jevt.value[/x/y/z], where x,y and z are levels in the JSON hierarchy."},
		{Type: "string", Name: "json.obj", Desc: "the full json message as a text string."},
		{Type: "string", Name: "jevt.value", ArgRequired: true, Desc: "alias for json.value, provided for backwards compatibility"},
		{Type: "string", Name: "jevt.obj", Desc: "alias for json.obj, provided for backwards compatibility"},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		panic(err)
		return nil
	}

	return C.CString(string(b))
}

func extract_str(pluginState unsafe.Pointer, evtnum uint64, field string, arg string, data []byte) (bool, string) {
	var res string
	var err error
	pCtx := (*pluginContext)(sinsp.Context(pluginState))

	// As a very quick sanity check, only try to extract all if
	// the first character is '{' or '['
	if !(data[0] == '{' || data[0] == '[') {
		return false, ""
	}

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {

		// Try to parse the data as json
		evtStr := string(data)

		pCtx.jdata, err = pCtx.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present
			return false, ""
		}
		pCtx.jdataEvtnum = evtnum
	}

	switch field {
	case "json.value", "jevt.value":
		if arg[0] == '/' {
			arg = arg[1:]
		}
		hc := strings.Split(arg, "/")

		val := pCtx.jdata.GetStringBytes(hc...)
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "json.obj", "jevt.obj":
		var out bytes.Buffer
		err = json.Indent(&out, data, "", "  ")
		if err != nil {
			return false, ""
		}
		res = string(out.Bytes())
	default:
		return false, ""
	}

	return true, res
}

//export plugin_extract_str
func plugin_extract_str(plgState unsafe.Pointer, evtnum uint64, field *C.char, arg *C.char, data *C.uint8_t, datalen uint32) *C.char {
	return (*C.char)(sinsp.WrapExtractStr(plgState, evtnum, unsafe.Pointer(field), unsafe.Pointer(arg), unsafe.Pointer(data), datalen, extract_str))
}

//export plugin_extract_u64
func plugin_extract_u64(plgState unsafe.Pointer, evtnum uint64, field *C.char, arg *C.char, data *C.uint8_t, datalen uint32, fieldPresent *uint32) uint64 {
	// No numeric fields for this plugin
	*fieldPresent = 0
	return 0
}


///////////////////////////////////////////////////////////////////////////////
// The following code is part of the plugin interface. Do not remove it.
///////////////////////////////////////////////////////////////////////////////

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, extract_str, nil)
}

func main() {
}
