#ifndef __UTIL_H_
#define __UTIL_H_

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void hex_dump(const void *p_buf, size_t len, const char *p_title)
{
    int i = 0;
	const unsigned char *p_data = (unsigned char *)p_buf;
	int remain_len = len, print_len = 0, count = 0;
	char linebuf[128] = { 0 };

	fprintf(stdout, "DUMP BUFFER %s HEX LENGTH:%lu\n", p_title, len);
	
	do
	{
		print_len = remain_len > 16 ? 16 : remain_len;
		for (i = 0; i < print_len; i++)
		{
			sprintf(linebuf + i * 3, "%02x ", (unsigned char)p_data[count * 16 + i]);
		}
		fprintf(stdout, "%s\n", linebuf);
		memset(linebuf, 0, 128);
		remain_len -= print_len;
		count++;
	}
	while (remain_len);
}

#endif