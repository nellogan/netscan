#include <argp.h>
#include <stdlib.h>

#include "net_scan.h"


const char *argp_program_version = "netscan 0.0.1";
const char *argp_program_bug_address = "<https://github.com/nellogan/netscan/issues>";

static char doc[] =
"netscan -- scan either an IPv4 address or a range of IPv4 addresses (CIDR notation) at port 443(HTTPS). "
"By default, will attempt a TCP connection. Send icmp packet(s) (via ping) if the -p switch is provided instead. Particularly "
"useful for scanning a LAN subnet (assuming permission to do so). This program is a proof of concept and not as "
"powerful as nmap but is straight forward, lightweight, and host discovery (even if ping is not available). Requires "
"the 'ping' commandline program to be installed to use the -p switch.";

static char args_doc[] = "IP_ADDR_OR_CIDR";

static struct argp_option options[] =
{
	{"ping_toggle", 'p', 0, 0, "Toggle that will attempt a TCP connection in lieu of a ping to determine if host or hosts are up.", 0},
	{ 0, 0, 0, 0, 0, 0 }
};

struct arguments
{
	char* args[1];
	bool ping_toggle;
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = static_cast<struct arguments*>(state->input);

	switch (key)
	{
		case 'p':
			arguments->ping_toggle = true;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 1)
				// Too many arguments.
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 1)
				// Not enough arguments.
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main (int argc, char **argv)
{
	struct arguments arguments;
	arguments.ping_toggle = false;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	Mode mode = arguments.ping_toggle == true ? Mode::PING : Mode::CONNECT;
    char* input = arguments.args[0];

    NetScan net_scan{};
    net_scan.DetermineAndRunOperation(input, mode);

	return 0;
}
