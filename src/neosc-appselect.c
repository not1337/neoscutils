/*
 * neosc-appselect - allows you to switch to a specified YubiKey NEO(-N) applet
 *
 * Copyright (c) 2015 Andreas Steinmetz, ast@domdv.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libneosc.h>

static void usage(void)
{
    fprintf(stderr,
	"Usage: neosc-appselect [-s <serial>|-u|-n] -N|-d|-o|-O|-p|-h\n"
	"-N             select NEO applet\n"
	"-d             select NDEF applet\n"
	"-o             select OATH applet\n"
	"-O             select OpenPGP applet\n"
	"-p             select PIV applet\n"
	"-s <serial>    use YubiKey with given serial number\n"
	"-u             use first USB attached YubiKey without serial number\n"
	"-n             use first NFC attached YubiKey\n"
	"-h             this help text\n");
    exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int r=1;
	int mode=0;
	int serial=NEOSC_ANY_YUBIKEY;
	void *ctx;

	while((c=getopt(argc,argv,"NdoOps:unh"))!=-1)switch(c)
	{
	case 'N':
		if(mode)usage();
		mode=1;
		break;
	case 'd':
		if(mode)usage();
		mode=2;
		break;
	case 'o':
		if(mode)usage();
		mode=3;
		break;
	case 'O':
		if(mode)usage();
		mode=4;
		break;
	case 'p':
		if(mode)usage();
		mode=5;
		break;
	case 's':
		if(serial!=NEOSC_ANY_YUBIKEY)usage();
		if((serial=atoi(optarg))<=NEOSC_ANY_YUBIKEY)usage();
		break;
	case 'u':
		if(serial!=NEOSC_ANY_YUBIKEY)usage();
		serial=NEOSC_USB_YUBIKEY;
		break;
	case 'n':
		if(serial!=NEOSC_ANY_YUBIKEY)usage();
		serial=NEOSC_NFC_YUBIKEY;
		break;

	case 'h':
	default:usage();
	}

	if(!mode)usage();

	if(neosc_pcsc_open(&ctx,serial))
	{
		fprintf(stderr,"device open error.\n");
		goto err1;
	}

	if(neosc_pcsc_lock(ctx))
	{
		fprintf(stderr,"device lock error.\n");
		goto err2;
	}

	switch(mode)
	{
	case 1:	if(neosc_neo_select(ctx,NULL))goto err3;
		break;
	case 2:	if(neosc_ndef_select(ctx))goto err3;
		break;
	case 3:	if(neosc_oath_select(ctx,NULL))goto err3;
		break;
	case 4:	if(neosc_pgp_select(ctx))goto err3;
		break;
	case 5:	if(neosc_piv_select(ctx))goto err3;
		break;
	}

	r=0;

err3:	if(r)fprintf(stderr,"applet select error.\n");
	neosc_pcsc_unlock(ctx);
err2:	neosc_pcsc_close(ctx);
err1:	return r;
}
