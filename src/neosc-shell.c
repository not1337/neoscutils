/*
 * neosc-shell - a configuration shell for the YubiKey NEO(-N)
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

#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <libneosc.h>

#define memclear(a,b,c) \
    do { memset(a,b,c); *(volatile char*)(a)=*(volatile char*)(a); } while(0)

#define MAXLEN	128

#define INT1	0
#define INT2	1
#define INT3	2
#define INT4	3
#define ARR	4

#define SERIAL		0
#define SLOT		1
#define CHALLENGE	2
#define URL		3
#define	TEXT		4
#define LANG		5
#define SCANMAP		6
#define MODE		7
#define CRTIMEOUT	8
#define AUTOEJECTTIME	9
#define TICKETFLAGS	10
#define CONFIGFLAGS	11
#define EXTENDEDFLAGS	12
#define ACCESSCODE	13
#define NEWACCESSCODE	14
#define SECRETKEY	15
#define PRIVATEID	16
#define PUBLICID	17
#define OMP		18
#define TT		19
#define MUI		20
#define IMF		21
#define PASSWORD	22
#define NEWPASSWORD	23
#define OTPNAME		24
#define OTPMODE		25
#define SHAMODE		26
#define OTPDIGITS	27

#define TOTALVARS	28

typedef struct
{
	char *name;
	int type;
	int valid;
	int len;
	union
	{
		int value;
		unsigned char data[MAXLEN+1];
	};
} VAR;

static int enable=0;

static VAR var[TOTALVARS]=
{
	{"serial",INT4,0,0},
	{"slot",INT1,0,0},
	{"challenge",ARR,0,0},
	{"url",ARR,0,0},
	{"text",ARR,0,0},
	{"lang",ARR,0,0},
	{"scanmap",ARR,0,0},
	{"mode",INT1,0,0},
	{"crtimeout",INT1,0,0},
	{"autoejecttime",INT2,0,0},
	{"ticketflags",INT1,0,0},
	{"configflags",INT1,0,0},
	{"extendedflags",INT1,0,0},
	{"accesscode",ARR,0,0},
	{"newaccesscode",ARR,0,0},
	{"secretkey",ARR,0,0},
	{"privateid",ARR,0,0},
	{"publicid",ARR,0,0},
	{"omp",INT1,0,0},
	{"tt",INT1,0,0},
	{"mui",INT4,0,0},
	{"imf",INT4,0,0},
	{"password",ARR,0,0},
	{"newpassword",ARR,0,0},
	{"otpname",ARR,0,0},
	{"otpmode",INT1,0,0},
	{"shamode",INT1,0,0},
	{"otpdigits",INT1,0,0},
};

static void varhelp(void)
{
	int i;

	printf("Variables:\n\n");
	for(i=0;i<TOTALVARS;i++)printf("\t%s (%s)\n",var[i].name,
		var[i].type==ARR?"array":"number");
	printf("\n"
	"Commands working with variables:\n"
	"\n"
	"set <variable> <value>\n"
	"\n"
	"\tSets a variable to the specified value.\n"
	"\tThe value may be prefixed by a modifier.\n"
	"\tIf no modifier is specified the value must be a decimal number.\n"
	"\tModifier are:\n"
	"\n"
	"\th:\t\ta hexadecimal number\n"
	"\tm:\t\ta modified hexadecimal (modhex) number\n"
	"\tb32:\t\ta base32 encoded number\n"
	"\tb64:\t\ta base64 encoded number\n"
	"\tt:<time>\ta time value, either 'now' for the current time or\n"
	"\t\t\ta time specified as 'yyyy-mm-dd HH:MM:SS'\n"
	"\t\t\t(array only)\n"
	"\ts:\t\ta character string (array only)\n"
	"\tr:<digits>\ta random of <digits> length (array only)\n"
	"\n"
	"clear <variable>\n"
	"\n"
	"\tUnsets a variable.\n"
	"\n"
	"show <variable>\n"
	"\n"
	"\tPrints a variable as hexadecimal number.\n"
	"\n"
	"print <variable>\n"
	"\n"
	"\tPrints a variable as decimal number (number only).\n"
	"\n"
	"modhex <variable>\n"
	"\n"
	"\tPrints a variable as modified hexadecimal number (array only).\n"
	"\n"
	"base32 <variable>\n"
	"\n"
	"\tPrints a variable base32 encoded (array only).\n"
	"\n"
	"base64 <variable>\n"
	"\n"
	"\tPrints a variable base64 encoded (array only).\n");
}

static void neohelp(void)
{
	printf("NEO Applet (CCID mode):\n\n"
	"Usage: neo <command>\n\n"
	"\tshow-info\t\tshow applet info\n"
	"\tshow-status\t\tshow applet status\n"
	"\tshow-serial\t\tshow device serial number\n"
	"\tshow-ndef\t\tshow ndef data (NFC only)\n"
	"\tcalc-yubiotp\t\tcalculate Yubico OTP (NFC only)\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\tcalc-hmac\t\tcalculate HMCA_SHA1 challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tchallenge\trequired, 1 to 64 bytes\n"
	"\t\totpdigits\toptional, if set (6-8) print otp format\n"
	"\tcalc-otp\t\tcalcuate Yubico OTP challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tchallenge\trequired, 6 bytes\n"
	"\tset-ndef\t\tconfigure NDEF message\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\turl\t\t(this or 'text' and 'lang'), the url to store\n"
	"\t\ttext\t\t(this and 'lang' or 'url'), the text to store\n"
	"\t\tlang\t\t(this and 'text' or 'url'), language to store\n"
	"\tset-scanmap\t\tconfigure device scan code map\n"
	"\t\tscanmap\t\toptional, 45 byte scan map\n"
	"\tset-mode\t\tconfigure device operation mode\n"
	"\t\tmode\t\trequired, operation mode (0-6)\n"
	"\t\tcrtimeout\trequired, challenge-response timeout\n"
	"\t\tautoejecttime\trequired, auto eject time\n"
	"\treset-slot\t\treset configuration of a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\tswap-slots\t\texchange both slots\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tupdate-slot\t\tupdate configuration options for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-hmac\t\tconfigure HMAC-SHA1 challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (20 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-otp\t\tconfigure Yubico OTP challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\toptional, private identity (6 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-hotp\t\tconfigure HOTP for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (20 bytes)\n"
	"\t\tomp\t\trequired, (0-255, 0 if not used)\n"
	"\t\ttt\t\trequired, (0-255, 0 if not used)\n"
	"\t\tmui\t\trequired, (0-99999999, -1 if not used)\n"
	"\t\timf\t\trequired, (0-0xffff0, increments of 16)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-yubiotp\t\tconfigure Yubico OTP for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\toptional, private identity (6 bytes)\n"
	"\t\tpublicid\toptional, public identity (1-16 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-password\t\tconfigure static password for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\trequired, private identity (6 bytes)\n"
	"\t\tpublicid\toptional, public identity (1-16 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n");
}

static void ndefhelp(void)
{
	printf("NDEF Applet (CCID mode):\n\n"
	"Usage: ndef <command>\n\n"
	"\tshow-cc\t\t\tshow ndef cc data (NFC only)\n"
	"\tshow-ndef\t\tshow ndef data (NFC only)\n");
}

static void oathhelp(void)
{
	printf("OATH Applet (CCID mode):\n\n"
	"Usage: oath <command>\n\n"
	"\tshow-info\t\tshow applet info\n"
	"\treset-all\t\treset applet\n"
	"\tset-password\t\tset/change/clear applet password\n"
	"\t\tpassword\toptional, current password (if any)\n"
	"\t\tnewpassword\toptional, new password (if any)\n"
	"\tcalc-otp\t\tcalculate named OTP entry\n"
	"\t\totpname\t\trequired, name of entry to be processed\n"
	"\t\tpassword\toptional, current password (if any)\n"
	"\tcalc-all-totp\t\tcalculate all TOTP entries\n"
	"\t\tpassword\toptional, current password (if any)\n"
	"\tlist-all\t\tlist all OTP entries\n"
	"\t\tpassword\toptional, current password (if any)\n"
	"\tdelete-entry\t\tdelete an OTP entry\n"
	"\t\totpname\t\trequired, name of entry to be processed\n"
	"\t\tpassword\toptional, current password (if any)\n"
	"\tadd-change-entry\tadd or modify an OTP entry\n"
	"\t\totpname\t\trequired, name of entry to be processed\n"
	"\t\totpmode\t\trequired, 0 for HOTP, 1 for TOTP\n"
	"\t\tshamode\t\trequired, 0 for SHA1, 1 for SHA256\n"
	"\t\totpdigits\trequired, output digit amount (6-8)\n"
	"\t\timf\t\trequired, initial moving factor for HOTP\n"
	"\t\tsecretkey\trequired, 20 bytes for SHA1, 32 for SHA256\n"
	"\t\tpassword\toptional, current password (if any)\n");
}

static void usbhelp(void)
{
	printf("NEO Applet (OTP mode):\n\n"
	"Usage: usb <command>\n\n"
	"\tshow-status\t\tshow applet status\n"
	"\tshow-serial\t\tshow device serial number\n"
	"\tcalc-hmac\t\tcalculate HMCA_SHA1 challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tchallenge\trequired, 1 to 64 bytes\n"
	"\t\totpdigits\toptional, if set (6-8) print otp format\n"
	"\tcalc-otp\t\tcalcuate Yubico OTP challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tchallenge\trequired, 6 bytes\n"
	"\tset-ndef\t\tconfigure NDEF message\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\turl\t\t(this or 'text' and 'lang'), the url to store\n"
	"\t\ttext\t\t(this and 'lang' or 'url'), the text to store\n"
	"\t\tlang\t\t(this and 'text' or 'url'), language to store\n"
	"\tset-scanmap\t\tconfigure device scan code map\n"
	"\t\tscanmap\t\toptional, 45 byte scan map\n"
	"\tset-mode\t\tconfigure device operation mode\n"
	"\t\tmode\t\trequired, operation mode (0-6)\n"
	"\t\tcrtimeout\trequired, challenge-response timeout\n"
	"\t\tautoejecttime\trequired, auto eject time\n"
	"\treset-slot\t\treset configuration of a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\tswap-slots\t\texchange both slots\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tupdate-slot\t\tupdate configuration options for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-hmac\t\tconfigure HMAC-SHA1 challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (20 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-otp\t\tconfigure Yubico OTP challenge-response\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\toptional, private identity (6 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-hotp\t\tconfigure HOTP for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (20 bytes)\n"
	"\t\tomp\t\trequired, (0-255, 0 if not used)\n"
	"\t\ttt\t\trequired, (0-255, 0 if not used)\n"
	"\t\tmui\t\trequired, (0-99999999, -1 if not used)\n"
	"\t\timf\t\trequired, (0-0xffff0, increments of 16)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-yubiotp\t\tconfigure Yubico OTP for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\toptional, private identity (6 bytes)\n"
	"\t\tpublicid\toptional, public identity (1-16 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n"
	"\tconfig-password\t\tconfigure static password for a slot\n"
	"\t\tslot\t\trequired, slot number(0 or 1)\n"
	"\t\tsecretkey\trequired, hash secret key (16 bytes)\n"
	"\t\tticketflags\trequired, ticket flags\n"
	"\t\tconfigflags\trequired, configuration flags\n"
	"\t\textendedflags\trequired, extended flags\n"
	"\t\tprivateid\trequired, private identity (6 bytes)\n"
	"\t\tpublicid\toptional, public identity (1-16 bytes)\n"
	"\t\taccesscode\toptional, current access code (6 bytes)\n"
	"\t\tnewaccesscode\toptional, new access code (6 bytes)\n");
}

static void help(char *item)
{
	if(item)
	{
		if(!strcmp(item,"var"))varhelp();
		else if(!strcmp(item,"neo"))neohelp();
		else if(!strcmp(item,"ndef"))ndefhelp();
		else if(!strcmp(item,"oath"))oathhelp();
		else if(!strcmp(item,"usb"))usbhelp();
		else item=NULL;
	}

	if(!item)
	{
		printf("Help items:\n"
		"\n"
		"var\thelp related to variables\n"
		"neo\thelp for neo applet commands (ccid mode)\n"
		"ndef\thelp for ndef applet commands (ccid mode)\n"
		"oath\thelp for oath applet commands (ccid mode)\n"
		"usb\thelp for usb related commands (otp mode)\n");
		return;
	}
}

static int varhandler(int mode,char *name,char *value)
{
	int r=-1;
	int i;
	int j;
	int k;
	int len=MAXLEN;
	unsigned long long val;
	char *eptr;
	struct tm tm;
	unsigned char bfr[2*MAXLEN+1];

	for(i=0;i<TOTALVARS;i++)if(!strcmp(var[i].name,name))break;
	if(i==TOTALVARS)goto fail;

	switch(mode)
	{
	case 0:	if(!strncmp(value,"h:",2))
		{
			if(neosc_util_hex_decode(value+2,strlen(value+2),bfr,
				&len))goto fail;
		}
		else if(!strncmp(value,"m:",2))
		{
			if(neosc_util_modhex_decode(value+2,strlen(value+2),bfr,
				&len))goto fail;
		}
		else if(!strncmp(value,"b64:",4))
		{
			if(neosc_util_base64_decode(value+4,strlen(value+4),bfr,
				&len))goto fail;
		}
		else if(!strncmp(value,"b32:",4))
		{
			if(neosc_util_base32_decode(value+4,strlen(value+4),bfr,
				&len))goto fail;
		}
		else if(!strncmp(value,"t:",2))
		{
			if(var[i].type!=ARR)goto fail;
			if(!strcmp(value+2,"now"))val=time(NULL);
			else
			{
				memset(&tm,0,sizeof(tm));
				if(strptime(value+2,"%n%Y-%m-%d%n%T",&tm))
					goto fail;
				val=mktime(&tm);
			}
			neosc_util_time_to_array((time_t)val,bfr,8);
			len=8;
		}
		else if(!strncmp(value,"s:",2))
		{
			if(var[i].type!=ARR)goto fail;
			if((len=strlen(value+2))>MAXLEN)goto fail;
			strcpy((char *)bfr,value+2);
		}
		else if(!strncmp(value,"r:",2))
		{
			if(var[i].type!=ARR)goto fail;
			val=strtoull(value+2,&eptr,10);
			if(eptr==value+2||*eptr)goto fail;
			if(val>MAXLEN)goto fail;
			len=(int)val;
			if(neosc_util_random(bfr,len))goto fail;
		}
		else
		{
			val=strtoull(value,&eptr,10);
			if(eptr==value||*eptr)goto fail;
			for(len=8,k=0,j=56;k<8;k++,j-=8)
				bfr[k]=(unsigned char)(val>>j);
		}
		if(var[i].type==ARR)
		{
			memcpy(var[i].data,bfr,len);
			var[i].len=len;
			var[i].data[len]=0;
		}
		else
		{
			for(var[i].value=0,j=0;j<len;j++)
			{
				var[i].value<<=8;
				var[i].value|=bfr[j];
			}
			switch(var[i].type)
			{
			case INT1:
				j=~0xff;
				break;
			case INT2:
				j=~0xffff;
				break;
			case INT3:
				j=~0xffff;
				break;
			case INT4:
				j=~0xffffff;
				break;
			}
			if((*value=='-'?-var[i].value:var[i].value)&j)goto fail;
		}
		var[i].valid=1;
		break;

	case 1:	var[i].valid=0;
		var[i].len=0;
		break;

	case 2:	if(!var[i].valid)strcpy((char *)bfr,"<undef>");
		else switch(var[i].type)
		{
		case INT1:
			sprintf((char *)bfr,"h:%02x",var[i].value);
			break;
		case INT2:
			sprintf((char *)bfr,"h:%04x",var[i].value);
			break;
		case INT3:
			sprintf((char *)bfr,"h:%06x",var[i].value);
			break;
		case INT4:
			sprintf((char *)bfr,"h:%08x",var[i].value);
			break;
		case ARR:
			strcpy((char *)bfr,"h:");
			len=sizeof(bfr)-2;
			if(neosc_util_hex_encode(var[i].data,var[i].len,
				(char *)bfr+2,&len))goto fail;
			break;
		}
		printf("%s\n",(char *)bfr);
		break;

	case 3:	if(var[i].type==ARR)goto fail;
		else if(!var[i].valid)strcpy((char *)bfr,"<undef>");
		else sprintf((char *)bfr,"%d",var[i].value);
		printf("%s\n",(char *)bfr);
		break;

	case 4:	len=sizeof(bfr);
		if(var[i].type!=ARR)goto fail;
		else if(!var[i].valid)strcpy((char *)bfr,"<undef>");
		else if(neosc_util_modhex_encode(var[i].data,var[i].len,
			(char *)bfr,&len))goto fail;
		printf("m:%s\n",(char *)bfr);
		break;

	case 5:	len=sizeof(bfr);
		if(var[i].type!=ARR)goto fail;
		else if(!var[i].valid)strcpy((char *)bfr,"<undef>");
		else if(neosc_util_base32_encode(var[i].data,var[i].len,
			(char *)bfr,&len))goto fail;
		printf("b32:%s\n",(char *)bfr);
		break;

	case 6:	len=sizeof(bfr);
		if(var[i].type!=ARR)goto fail;
		else if(!var[i].valid)strcpy((char *)bfr,"<undef>");
		else if(neosc_util_base64_encode(var[i].data,var[i].len,
			(char *)bfr,&len))goto fail;
		printf("b64:%s\n",(char *)bfr);
		break;

	default:goto fail;
	}

	r=0;

fail:	memclear(&tm,0,sizeof(tm));
	memclear(&val,0,sizeof(val));
	memclear(bfr,0,sizeof(bfr));
	return r;
}

static int neohandler(char *cmd)
{
	int mode=-1;
	int serial=0;
	int r=-1;
	int val;
	int len;
	void *ctx;
	NEOSC_NEO_INFO info;
	NEOSC_STATUS status;
	NEOSC_NDEF ndefdata;
	unsigned char bfr[MAXLEN];
	char txt[2*MAXLEN+1];

	if(var[SERIAL].valid)serial=var[SERIAL].value;

	if(!strcmp(cmd,"show-info"))mode=0;
	else if(!strcmp(cmd,"show-status"))mode=1;
	else if(!strcmp(cmd,"show-ndef"))mode=2;
	else if(!strcmp(cmd,"calc-yubiotp"))
	{
		if(!var[SLOT].valid)goto err1;
		mode=3;
	}
	else if(!strcmp(cmd,"calc-hmac"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[CHALLENGE].valid)goto err1;
		mode=4;
	}
	else if(!strcmp(cmd,"calc-otp"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[CHALLENGE].valid)goto err1;
		mode=5;
	}
	else if(!strcmp(cmd,"set-ndef"))
	{
		if(!var[SLOT].valid)goto err1;
		mode=6;
	}
	else if(!strcmp(cmd,"set-scanmap"))mode=7;
	else if(!strcmp(cmd,"set-mode"))
	{
		if(!var[MODE].valid)goto err1;
		if(var[MODE].value==0x03&&enable<3)goto err1;
		if(!var[CRTIMEOUT].valid)goto err1;
		if(!var[AUTOEJECTTIME].valid)goto err1;
		mode=8;
	}
	else if(!strcmp(cmd,"reset-slot"))
	{
		if(!(enable&1))goto err1;
		if(!var[SLOT].valid)goto err1;
		mode=9;
	}
	else if(!strcmp(cmd,"swap-slots"))mode=10;
	else if(!strcmp(cmd,"update-slot"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		mode=11;
	}
	else if(!strcmp(cmd,"config-hmac"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		mode=12;
	}
	else if(!strcmp(cmd,"config-otp"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		mode=13;
	}
	else if(!strcmp(cmd,"config-hotp"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		if(!var[OMP].valid)goto err1;
		if(!var[TT].valid)goto err1;
		if(!var[MUI].valid)goto err1;
		if(!var[IMF].valid)goto err1;
		mode=14;
	}
	else if(!strcmp(cmd,"config-yubiotp"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		mode=15;
	}
	else if(!strcmp(cmd,"config-password"))
	{
		if(!var[SLOT].valid)goto err1;
		if(!var[TICKETFLAGS].valid)goto err1;
		if(!var[CONFIGFLAGS].valid)goto err1;
		if(!var[EXTENDEDFLAGS].valid)goto err1;
		mode=16;
	}
	else if(!strcmp(cmd,"show-serial"))mode=17;
	else goto err1;

	if(neosc_pcsc_open(&ctx,serial))goto err1;
	if(neosc_pcsc_lock(ctx))goto err2;
	if(neosc_neo_select(ctx,&info))goto err3;

	switch(mode)
	{
	case 0:	printf("version: %d.%d.%d\n",info.major,info.minor,info.build);
		printf("pgmseq: %d\n",info.pgmseq);
		printf("touchlevel: %d\n",info.touchlevel);
		printf("mode: %d\n",info.mode);
		printf("crtimeout: %d\n",info.crtimeout);
		printf("autoejecttime: %d\n",info.autoejecttime);
		printf("config 1 valid: %s\n",info.config1?"yes":"no");
		printf("config 2 valid: %s\n",info.config2?"yes":"no");
		printf("config 1 needs button: %s\n",info.touch1?"yes":"no");
		printf("config 2 needs button: %s\n",info.touch2?"yes":"no");
		printf("led behaviour: %s\n",info.ledinv?"inverted":"normal");
		r=0;
		break;

	case 1:	if((r=neosc_neo_read_status(ctx,&status)))break;
		printf("version: %d.%d.%d\n",status.major,status.minor,
			status.build);
		printf("pgmseq: %d\n",status.pgmseq);
		printf("touchlevel: %d\n",status.touchlevel);
		printf("config 1 valid: %s\n",status.config1?"yes":"no");
		printf("config 2 valid: %s\n",status.config2?"yes":"no");
		printf("config 1 needs button: %s\n",status.touch1?"yes":"no");
		printf("config 2 needs button: %s\n",status.touch2?"yes":"no");
		printf("led behaviour: %s\n",status.ledinv?"inverted":"normal");
		break;

	case 2:	if((r=neosc_neo_read_ndef(ctx,&ndefdata)))break;
		if(ndefdata.type==NEOSC_NDEF_TEXT)
		{
			printf("language: %s\n",ndefdata.language);
			printf("text: %s\n",ndefdata.payload);
		}
		else printf("url: %s\n",ndefdata.payload);
		break;

	case 3:	if((r=neosc_neo_read_yubiotp(ctx,var[SLOT].value,txt,
			sizeof(txt))))break;
		printf("otp:%s\n",txt);
		break;

	case 4:	if((r=neosc_neo_read_hmac(ctx,var[SLOT].value,
		    var[CHALLENGE].data,var[CHALLENGE].len,bfr,sizeof(bfr))))
			break;
		if(var[OTPDIGITS].valid)
		{
			if((r=neosc_util_sha1_to_otp(bfr,NEOSC_SHA1_SIZE,
				var[OTPDIGITS].value,&val)))break;
			switch(var[OTPDIGITS].value)
			{
			case 6:	printf("otp:%06d\n",val);
				break;
			case 7:	printf("otp:%07d\n",val);
				break;
			case 8:	printf("otp:%08d\n",val);
				break;
			default:r=-1;
				break;
			}
		}
		else
		{
			len=sizeof(txt);
			if((r=neosc_util_hex_encode(bfr,NEOSC_SHA1_SIZE,txt,
				&len)))break;
			printf("h:%s\n",txt);
		}
		break;

	case 5:	if((r=neosc_neo_read_otp(ctx,var[SLOT].value,
		    var[CHALLENGE].data,var[CHALLENGE].len,bfr,sizeof(bfr))))
			break;
		len=sizeof(txt);
		if((r=neosc_util_modhex_encode(bfr,16,txt,&len)))break;
		printf("m:%s\n",txt);
		break;

	case 6:	r=neosc_neo_write_ndef(ctx,var[SLOT].value,
			var[URL].valid?(char *)var[URL].data:NULL,
			var[TEXT].valid?(char *)var[TEXT].data:NULL,
			var[LANG].valid?(char *)var[LANG].data:NULL,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 7:	r=neosc_neo_write_scanmap(ctx,
			var[SCANMAP].valid?var[SCANMAP].data:NULL,
			var[SCANMAP].len);
		break;

	case 8:	r=neosc_neo_setmode(ctx,var[MODE].value,var[CRTIMEOUT].value,
			var[AUTOEJECTTIME].value);
		break;

	case 9:	r=neosc_neo_reset(ctx,var[SLOT].value);
		break;

	case 10:r=neosc_neo_swap(ctx,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 11:r=neosc_neo_update(ctx,var[SLOT].value,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 12:r=neosc_neo_hmac(ctx,var[SLOT].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 13:r=neosc_neo_otp(ctx,var[SLOT].value,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 14:r=neosc_neo_hotp(ctx,var[SLOT].value,var[OMP].value,
			var[TT].value,var[MUI].value,var[IMF].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 15:r=neosc_neo_yubiotp(ctx,var[SLOT].value,
			var[PUBLICID].valid?var[PUBLICID].data:NULL,
			var[PUBLICID].len,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 16:r=neosc_neo_passwd(ctx,var[SLOT].value,
			var[PUBLICID].valid?var[PUBLICID].data:NULL,
			var[PUBLICID].len,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 17:if((r=neosc_neo_read_serial(ctx,&val)))break;
		printf("serial: %d\n",val);
		break;
	}

err3:	neosc_pcsc_unlock(ctx);
err2:	neosc_pcsc_close(ctx);
err1:	memclear(&info,0,sizeof(info));
	memclear(&status,0,sizeof(status));
	memclear(&ndefdata,0,sizeof(ndefdata));
	memclear(&serial,0,sizeof(serial));
	memclear(&val,0,sizeof(val));
	memclear(bfr,0,sizeof(bfr));
	memclear(txt,0,sizeof(txt));
	return r;
}

static int ndefhandler(char *cmd)
{
	int r=-1;
	int mode=-1;
	int serial=0;
	void *ctx;
	NEOSC_NDEF_CC ccdata;
	NEOSC_NDEF ndefdata;

	if(var[SERIAL].valid)serial=var[SERIAL].value;

	if(!strcmp(cmd,"show-cc"))mode=0;
	else if(!strcmp(cmd,"show-ndef"))mode=1;
	else goto err1;

	if(neosc_pcsc_open(&ctx,serial))goto err1;
	if(neosc_pcsc_lock(ctx))goto err2;
	if(neosc_ndef_select(ctx))goto err3;

	switch(mode)
	{
	case 0:	if((r=neosc_ndef_read_cc(ctx,&ccdata)))break;
		printf("version: %02x\n",ccdata.version);
		printf("mle: %04x\n",ccdata.mle);
		printf("mlc: %04x\n",ccdata.mlc);
		printf("fileid: %04x\n",ccdata.fileid);
		printf("ndef_max: %04x\n",ccdata.ndef_max);
		printf("rcond: %02x\n",ccdata.rcond);
		printf("wcond: %02x\n",ccdata.wcond);
		break;

	case 1:	if((r=neosc_ndef_read_ndef(ctx,&ndefdata)))break;
		if(ndefdata.type==NEOSC_NDEF_TEXT)
		{
			printf("language: %s\n",ndefdata.language);
			printf("text: %s\n",ndefdata.payload);
		}
		else printf("url: %s\n",ndefdata.payload);
		break;
	}

err3:	neosc_pcsc_unlock(ctx);
err2:	neosc_pcsc_close(ctx);
err1:	memclear(&serial,0,sizeof(serial));
	memclear(&ccdata,0,sizeof(ccdata));
	memclear(&ndefdata,0,sizeof(ndefdata));
	return r;
}

static int oathhandler(char *cmd)
{
	int r=-1;
	int mode=-1;
	int serial=0;
	int len;
	int i;
	int total;
	void *ctx;
	NEOSC_OATH_LIST *list;
	NEOSC_OATH_RESPONSE *results;
	NEOSC_OATH_RESPONSE result;
	NEOSC_OATH_INFO info;
	char txt[2*MAXLEN+1];

	if(var[SERIAL].valid)serial=var[SERIAL].value;

	if(!strcmp(cmd,"show-info"))mode=0;
	else if(!strcmp(cmd,"reset-all"))
	{
		if(!(enable&1))goto err1;
		mode=1;
	}
	else if(!strcmp(cmd,"set-password"))mode=2;
	else if(!strcmp(cmd,"calc-otp"))mode=3;
	else if(!strcmp(cmd,"calc-all-totp"))mode=4;
	else if(!strcmp(cmd,"list-all"))mode=5;
	else if(!strcmp(cmd,"delete-entry"))mode=6;
	else if(!strcmp(cmd,"add-change-entry"))
	{
		if(!var[OTPMODE].valid)goto err1;
		if(!var[SHAMODE].valid)goto err1;
		if(!var[OTPDIGITS].valid)goto err1;
		if(!var[IMF].valid)goto err1;
		mode=7;
	}
	else goto err1;

	if(neosc_pcsc_open(&ctx,serial))goto err1;
	if(neosc_pcsc_lock(ctx))goto err2;
	if(neosc_oath_select(ctx,&info))goto err3;

	if(info.protected&&mode>1)
	{
		if(!var[PASSWORD].valid)goto err3;
		if(neosc_oath_unlock(ctx,(char *)var[PASSWORD].data,&info))
			goto err3;
	}

	switch(mode)
	{
	case 0:	len=sizeof(txt);
		if(neosc_util_hex_encode(info.identity,8,txt,&len))break;
		printf("version: %d.%d.%d\n",info.major,info.minor,info.build);
		printf("identity: %s\n",txt);
		printf("protected: %s\n",info.protected?"yes":"no");
		r=0;
		break;

	case 1:	r=neosc_oath_reset(ctx);
		break;

	case 2:	r=neosc_oath_chgpass(ctx,
			var[NEWPASSWORD].valid?(char *)var[NEWPASSWORD].data:"",
			&info);
		break;

	case 3:	if((r=neosc_oath_calc_single(ctx,
			var[OTPNAME].valid?(char *)var[OTPNAME].data:NULL,
			time(NULL),&result)))break;
		switch(result.digits)
		{
		case 6:	printf("otp: %06d\n",result.value);
			break;
		case 7:	printf("otp: %07d\n",result.value);
			break;
		case 8:	printf("otp: %08d\n",result.value);
			break;
		default:r=-1;
			break;
		}
		break;

	case 4:	if((r=neosc_oath_calc_all(ctx,time(NULL),&results,&total)))
			break;
		for(i=0;i<total;i++)
		{
			switch(results[i].digits)
			{
			case 6:	printf("totp: %06d %s\n",results[i].value,
					results[i].name);
				break;
			case 7:	printf("totp: %07d %s\n",results[i].value,
					results[i].name);
				break;
			case 8:	printf("totp: %08d %s\n",results[i].value,
					results[i].name);
				break;
			default:r=-1;
				break;
			}
			memclear(results[i].name,0,strlen(results[i].name));
			memclear(&results[i].digits,0,
				sizeof(results[i].digits));
			memclear(&results[i].value,0,sizeof(results[i].value));
		}
		if(results)free(results);
		break;

	case 5:	if((r=neosc_oath_list_all(ctx,&list,&total)))break;
		for(i=0;i<total;i++)
		{
			printf("%s-%s: %s\n",
			    list[i].otpmode==NEOSC_OATH_HOTP?"hotp":"totp",
			    list[i].shamode==NEOSC_OATH_SHA1?"sha1":"sha256",
			    list[i].name);
			memclear(list[i].name,0,sizeof(list[i].name));
			memclear(&list[i].otpmode,0,sizeof(list[i].otpmode));
			memclear(&list[i].shamode,0,sizeof(list[i].shamode));
		}
		if(list)free(list);
		break;

	case 6:	r=neosc_oath_delete(ctx,
			var[OTPNAME].valid?(char *)var[OTPNAME].data:NULL);
		break;

	case 7:	if((r=neosc_oath_add(ctx,
			var[OTPNAME].valid?(char *)var[OTPNAME].data:NULL,
			var[OTPMODE].value,var[SHAMODE].value,
			var[OTPDIGITS].value,(unsigned int)var[IMF].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len)))break;
		if((r=neosc_util_qrurl(
			var[OTPNAME].valid?(char *)var[OTPNAME].data:NULL,
			var[OTPMODE].value,var[SHAMODE].value,
			var[OTPDIGITS].value,(unsigned int)var[IMF].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,txt,sizeof(txt))))break;
		printf("url: %s\n",txt);
		break;
	}

err3:	neosc_pcsc_unlock(ctx);
err2:	neosc_pcsc_close(ctx);
err1:	memclear(&serial,0,sizeof(serial));
	memclear(&total,0,sizeof(total));
	memclear(&info,0,sizeof(info));
	memclear(&result,0,sizeof(result));
	memclear(txt,0,sizeof(txt));
	return r;
}

static int usbhandler(char *cmd)
{
	int mode=-1;
	int serial=0;
	int r=-1;
	int val;
	int len;
	int usbmode;
	void *ctx;
	NEOSC_STATUS status;
	unsigned char bfr[MAXLEN];
	char txt[2*MAXLEN+1];

	if(var[SERIAL].valid)serial=var[SERIAL].value;

	if(!strcmp(cmd,"show-status"))mode=1;
	else if(!strcmp(cmd,"show-serial"))mode=2;
	else if(!strcmp(cmd,"show-mode"))mode=3;
	else if(!strcmp(cmd,"calc-hmac"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[CHALLENGE].valid)goto fail;
		mode=4;
	}
	else if(!strcmp(cmd,"calc-otp"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[CHALLENGE].valid)goto fail;
		mode=5;
	}
	else if(!strcmp(cmd,"set-ndef"))
	{
		if(!var[SLOT].valid)goto fail;
		mode=6;
	}
	else if(!strcmp(cmd,"set-scanmap"))mode=7;
	else if(!strcmp(cmd,"set-mode"))
	{
		if(!var[MODE].valid)goto fail;
		if(var[MODE].value==0x03&&enable<3)goto fail;
		if(!var[CRTIMEOUT].valid)goto fail;
		if(!var[AUTOEJECTTIME].valid)goto fail;
		mode=8;
	}
	else if(!strcmp(cmd,"reset-slot"))
	{
		if(!(enable&1))goto fail;
		if(!var[SLOT].valid)goto fail;
		mode=9;
	}
	else if(!strcmp(cmd,"swap-slots"))mode=10;
	else if(!strcmp(cmd,"update-slot"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		mode=11;
	}
	else if(!strcmp(cmd,"config-hmac"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		mode=12;
	}
	else if(!strcmp(cmd,"config-otp"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		mode=13;
	}
	else if(!strcmp(cmd,"config-hotp"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		if(!var[OMP].valid)goto fail;
		if(!var[TT].valid)goto fail;
		if(!var[MUI].valid)goto fail;
		if(!var[IMF].valid)goto fail;
		mode=14;
	}
	else if(!strcmp(cmd,"config-yubiotp"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		mode=15;
	}
	else if(!strcmp(cmd,"config-password"))
	{
		if(!var[SLOT].valid)goto fail;
		if(!var[TICKETFLAGS].valid)goto fail;
		if(!var[CONFIGFLAGS].valid)goto fail;
		if(!var[EXTENDEDFLAGS].valid)goto fail;
		mode=16;
	}
	else goto fail;

	if(neosc_usb_open(&ctx,serial,&usbmode))goto fail;

	switch(mode)
	{
	case 1:	if((r=neosc_usb_read_status(ctx,&status)))break;
		printf("version: %d.%d.%d\n",status.major,status.minor,
			status.build);
		printf("pgmseq: %d\n",status.pgmseq);
		printf("touchlevel: %d\n",status.touchlevel);
		printf("config 1 valid: %s\n",status.config1?"yes":"no");
		printf("config 2 valid: %s\n",status.config2?"yes":"no");
		printf("config 1 needs button: %s\n",status.touch1?"yes":"no");
		printf("config 2 needs button: %s\n",status.touch2?"yes":"no");
		printf("led behaviour: %s\n",status.ledinv?"inverted":"normal");
		break;

	case 2:	if((r=neosc_usb_read_serial(ctx,&val)))break;
		printf("serial: %d\n",val);
		break;

	case 3:	printf("mode: %d\n",usbmode);
		r=0;
		break;

	case 4:	if((r=neosc_usb_read_hmac(ctx,var[SLOT].value,
		    var[CHALLENGE].data,var[CHALLENGE].len,bfr,sizeof(bfr))))
			break;
		if(var[OTPDIGITS].valid)
		{
			if((r=neosc_util_sha1_to_otp(bfr,NEOSC_SHA1_SIZE,
				var[OTPDIGITS].value,&val)))break;
			switch(var[OTPDIGITS].value)
			{
			case 6:	printf("otp:%06d\n",val);
				break;
			case 7:	printf("otp:%07d\n",val);
				break;
			case 8:	printf("otp:%08d\n",val);
				break;
			default:r=-1;
				break;
			}
		}
		else
		{
			len=sizeof(txt);
			if((r=neosc_util_hex_encode(bfr,NEOSC_SHA1_SIZE,txt,
				&len)))break;
			printf("h:%s\n",txt);
		}
		break;

	case 5:	if((r=neosc_usb_read_otp(ctx,var[SLOT].value,
		    var[CHALLENGE].data,var[CHALLENGE].len,bfr,sizeof(bfr))))
			break;
		len=sizeof(txt);
		if((r=neosc_util_modhex_encode(bfr,16,txt,&len)))break;
		printf("m:%s\n",txt);
		break;

	case 6:	r=neosc_usb_write_ndef(ctx,var[SLOT].value,
			var[URL].valid?(char *)var[URL].data:NULL,
			var[TEXT].valid?(char *)var[TEXT].data:NULL,
			var[LANG].valid?(char *)var[LANG].data:NULL,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 7:	r=neosc_usb_write_scanmap(ctx,
			var[SCANMAP].valid?var[SCANMAP].data:NULL,
			var[SCANMAP].len);
		break;

	case 8:	r=neosc_usb_setmode(ctx,var[MODE].value,var[CRTIMEOUT].value,
			var[AUTOEJECTTIME].value);
		break;

	case 9:	r=neosc_usb_reset(ctx,var[SLOT].value);
		break;

	case 10:r=neosc_usb_swap(ctx,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 11:r=neosc_usb_update(ctx,var[SLOT].value,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 12:r=neosc_usb_hmac(ctx,var[SLOT].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 13:r=neosc_usb_otp(ctx,var[SLOT].value,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 14:r=neosc_usb_hotp(ctx,var[SLOT].value,var[OMP].value,
			var[TT].value,var[MUI].value,var[IMF].value,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 15:r=neosc_usb_yubiotp(ctx,var[SLOT].value,
			var[PUBLICID].valid?var[PUBLICID].data:NULL,
			var[PUBLICID].len,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;

	case 16:r=neosc_usb_passwd(ctx,var[SLOT].value,
			var[PUBLICID].valid?var[PUBLICID].data:NULL,
			var[PUBLICID].len,
			var[PRIVATEID].valid?var[PRIVATEID].data:NULL,
			var[PRIVATEID].len,
			var[SECRETKEY].valid?var[SECRETKEY].data:NULL,
			var[SECRETKEY].len,var[TICKETFLAGS].value,
			var[CONFIGFLAGS].value,var[EXTENDEDFLAGS].value,
			var[NEWACCESSCODE].valid?var[NEWACCESSCODE].data:NULL,
			var[NEWACCESSCODE].len,
			var[ACCESSCODE].valid?var[ACCESSCODE].data:NULL,
			var[ACCESSCODE].len);
		break;
	}

	neosc_usb_close(ctx);

fail:	memclear(&status,0,sizeof(status));
	memclear(&serial,0,sizeof(serial));
	memclear(&val,0,sizeof(val));
	memclear(bfr,0,sizeof(bfr));
	memclear(txt,0,sizeof(txt));
	return r;
}

static int parseline(char *line)
{
	char *cmd=NULL;
	char *varname=NULL;
	char *varvalue=NULL;

	if(!(cmd=strtok(line," \t\r\n")))return 0;

	if(!strcmp(cmd,"set"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(!(varvalue=strtok(NULL,"\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(0,varname,varvalue);
	}
	else if(!strcmp(cmd,"clear"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(1,varname,varvalue);
	}
	else if(!strcmp(cmd,"show"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(2,varname,varvalue);
	}
	else if(!strcmp(cmd,"print"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(3,varname,varvalue);
	}
	else if(!strcmp(cmd,"modhex"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(4,varname,varvalue);
	}
	else if(!strcmp(cmd,"base32"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(5,varname,varvalue);
	}
	else if(!strcmp(cmd,"base64"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return varhandler(6,varname,varvalue);
	}
	else if(!strcmp(cmd,"neo"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return neohandler(varname);
	}
	else if(!strcmp(cmd,"ndef"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return ndefhandler(varname);
	}
	else if(!strcmp(cmd,"oath"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return oathhandler(varname);
	}
	else if(!strcmp(cmd,"usb"))
	{
		if(!(varname=strtok(NULL," \t\r\n")))return -1;
		if(strtok(NULL,"\r\n"))return -1;
		return usbhandler(varname);
	}
	else if(!strcmp(cmd,"help"))
	{
		varname=strtok(NULL," \t\r\n");
		if(varname)if(strtok(NULL,"\r\n"))return -1;
		help(varname);
		return 0;
	}
	else if(!strcmp(cmd,"quit"))
	{
		if(strtok(NULL,"\r\n"))return -1;
		return 1;
	}
	else return -1;
}

static int lineloop(char *prompt,int errmode,int verbose,int quiet)
{
	int len;
	char *line;
	HIST_ENTRY *h;
	HIST_ENTRY **l;

	using_history();

	if(!quiet)printf("READY (enter 'help' for help, 'quit' for exit)\n");

	while(1)
	{
		if(!(line=readline(prompt)))
		{
			if(verbose)printf("BYE\n");
			if((l=history_list()))for(;*l;l++)
			    memclear((*l)->line,0,strlen((*l)->line));
			for(len=0;len<TOTALVARS;len++)
				memclear(&var[len],0,sizeof(var[len]));
			return 0;
		}
		len=strlen(line);
		while(len)if(line[len-1]!=' '&&line[len-1]!='\t')break;
		else line[--len]=0;
		if(!len)continue;

		if(history_length&&(h=history_get(history_length)))
		{
			if(strcmp(h->line,line))add_history(line);
		}
		else add_history(line);

		switch(parseline(line))
		{
		case 0:	if(verbose)printf("OK\n");
			memclear(line,0,len);
			free(line);
			break;
		case 1:	if(verbose)printf("BYE\n");
			memclear(line,0,len);
			free(line);
			if((l=history_list()))for(;*l;l++)
			    memclear((*l)->line,0,strlen((*l)->line));
			for(len=0;len<TOTALVARS;len++)
				memclear(&var[len],0,sizeof(var[len]));
			return 0;
		case -1:if(!quiet)printf("ERROR\n");
			memclear(line,0,len);
			free(line);
			if(errmode)
			{
				if((l=history_list()))for(;*l;l++)
				    memclear((*l)->line,0,strlen((*l)->line));
				for(len=0;len<TOTALVARS;len++)
					memclear(&var[len],0,sizeof(var[len]));
				return -1;
			}
			break;
		}
	}

}

static void usage(void)
{
	fprintf(stderr,"Usage: neosc-shell <options>\n"
	  "-s <serial>\tuse YubiKey with given serial number\n"
	  "-u\t\tuse first USB attached YubiKey without serial number\n"
	  "-n\t\tuse first NFC attached YubiKey\n"
	  "-f\t\tenable commands that reset all configuration data\n"
	  "-F\t\tenable commands that may brick your device (requires -f too)\n"
	  "-q\t\tbe more quiet\n"
	  "-v\t\tbe more verbose\n"
	  "-e\t\tterminate in case of error\n"
	  "-N\t\tdo not print a prompt\n"
	  "-h\t\tthis help text\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int c;
	int verbose=0;
	int quiet=0;
	int errmode=0;
	int noprompt=0;
	int serial=NEOSC_ANY_YUBIKEY;

	signal(SIGHUP,SIG_IGN);
	signal(SIGINT,SIG_IGN);
	signal(SIGTERM,SIG_IGN);
	signal(SIGQUIT,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);

	while((c=getopt(argc,argv,"s:unfFqveNh"))!=-1)switch(c)
	{
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

	case 'f':
		if(enable&1)usage();
		enable|=1;
		break;
	case 'F':
		if(enable&2)usage();
		enable|=2;
		break;
	case 'q':
		if(quiet||verbose)usage();
		quiet=1;
		break;
	case 'v':
		if(quiet||verbose)usage();
		verbose=1;
		break;
	case 'e':
		if(errmode)usage();
		errmode=1;
		break;
	case 'N':
		if(noprompt)usage();
		noprompt=1;
		break;
	case 'h':
	default:usage();
	}

	if(serial!=NEOSC_ANY_YUBIKEY)
	{
		var[SERIAL].value=serial;
		var[SERIAL].valid=1;
	}

	if(lineloop(noprompt?NULL:"> ",errmode,verbose,quiet))return 1;
	return 0;
}
