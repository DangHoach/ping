#include <iostream>
#include "Ping.h"
using namespace std;

int main(int argc, char **argv) {
	Ping *ping = new Ping();
	ping->common_ping_main();
	return 0;
}
