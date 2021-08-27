/* Reference "dummy" plugin, similar to the dummy plugin in
   libsinsp-plugin-sdk-go repo, but written in C */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "scap.h"
#include "plugin_info.h"

struct dummy_plugin_info_2 {
};

static const char *pl_required_api_version = "1.0.0";
static uint32_t    pl_type                 = TYPE_SOURCE_PLUGIN;
static uint32_t    pl_id                   = 4;
static const char *pl_name                 = "dummy_c";
static const char *pl_desc                 = "do almost nothing, c-style";
static const char *pl_contact              = "github.com/mstemm/plugins";
static const char *pl_version              = "0.0.1";
static const char *pl_event_source         = "dummy";
static const char *pl_fields               = "[{\"type\":\"uint64\", \"name\":\"dummy.count\", \"desc\":\"TBD\"}]";
static const char *pl_evt_prefix           = "dummy";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct dummy_plugin_state
{
	char last_error[100];

	// Temporary buffer used in plugin_event_to_string
	char buf[1024];
} dummy_plugin_state;

typedef struct dummy_plugin_instance
{
	int count;

	// Temporary buffer used in plugin_next()
	char buf[256];
} dummy_plugin_instance;

char* plugin_get_required_api_version()
{
	return strdup(pl_required_api_version);
}

uint32_t plugin_get_type()
{
	return pl_type;
}

ss_plugin_t* plugin_init(char* config, int32_t* rc)
{
	dummy_plugin_state *ret = malloc(sizeof(dummy_plugin_state));
	ret->last_error[0] = '\0';

	*rc = SCAP_SUCCESS;

	return ret;
}

void plugin_destroy(ss_plugin_t* s)
{
	free(s);
}

char* plugin_get_last_error(ss_plugin_t* s)
{
	dummy_plugin_state *state = (dummy_plugin_state *) s;

	return strdup(state->last_error);
}

uint32_t plugin_get_id()
{
	return pl_id;
}

char* plugin_get_name()
{
	return strdup(pl_name);

}

char* plugin_get_description()
{
	return strdup(pl_desc);
}

char* plugin_get_contact()
{
	return strdup(pl_contact);
}


char* plugin_get_version()
{
	return strdup(pl_version);
}

char* plugin_get_event_source()
{
	return strdup(pl_event_source);
}

char* plugin_get_fields()
{
	return strdup(pl_fields);
}

ss_instance_t* plugin_open(ss_plugin_t* s, char* params, int32_t* rc)
{

	dummy_plugin_instance *ret = (dummy_plugin_instance *) malloc(sizeof(dummy_plugin_instance));

	ret->count = 0;

	*rc = SCAP_SUCCESS;

	return ret;
}

void plugin_close(ss_plugin_t* s, ss_instance_t* h)
{
	free(h);
}

int32_t plugin_next(ss_plugin_t* s, ss_instance_t* h, ss_plugin_event **evt)
{
	dummy_plugin_instance *i = (dummy_plugin_instance *) h;
	i->count++;

	snprintf(i->buf, sizeof(i->buf)-1, "%s%d", pl_evt_prefix, i->count);

	struct ss_plugin_event *ret = (struct ss_plugin_event *) malloc(sizeof(ss_plugin_event));

	ret->data = strdup(i->buf);
	ret->datalen = strlen(ret->data);
	ret->ts = (uint64_t) -1;

	*evt = ret;

	return SCAP_SUCCESS;
}

char *plugin_event_to_string(ss_plugin_t *s, const uint8_t *data, uint32_t datalen)
{
	dummy_plugin_state *state = (dummy_plugin_state *) s;

	snprintf(state->buf, sizeof(state->buf)-1, "evt-to-string(len=%d): %.*s", datalen, datalen, (char *) data);

	return strdup(state->buf);
}

int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	size_t prefix_len = strlen(pl_evt_prefix);

	for(uint32_t i=0; i < num_fields; i++)
	{
		ss_plugin_extract_field *field = &(fields[i]);

		if(strcmp(field->field, "dummy.count") != 0 ||
		   strncmp((char *) evt->data, pl_evt_prefix, prefix_len) != 0 ||
		   evt->datalen - prefix_len <= 0)
		{
			field->field_present = 0;
		}
		else
		{
			field->res_u64 = strtoull(evt->data + prefix_len, NULL, 10);
			field->field_present = 1;
		}
	}

	return SCAP_SUCCESS;

}
