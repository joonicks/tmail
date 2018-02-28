#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#define MSGLEN		2000
#define USER_ID		48 /* apache */
#define GROUP_ID	48 /* apache */
#define M_CONTROL	1
#define	M_DATA		2
#define CHROOTDIR	"/home/tmail"
#define MAILLOG		"tmail.log"
#define MAILPID		"tmail.pid"
#define DOMFILE		"maildomains"
#define ADDRLIST	"mailaddrlist"
#define MYNAME		"mail.joonicks.eu"

// ip address length = 15+1

char gsockdata[MSGLEN];
char dash[2] = "-";
int logfile;
unsigned char attr[256];
time_t now;

/* statistics */

time_t	lastsavedmail,uptime;
off_t	logfilesize;
int	receivedmails;
int	savedmails;
int	discardedmails;
int	relayrejects;
int	connections;
int	newinboxes;
int	spam_mails;

typedef struct doment
{
	struct	doment *next;
	char	dom[1];

} doment;

typedef struct mailcon
{
	struct	mailcon *next;
	struct	sockaddr_in sai;
	char	rest[MSGLEN];
	char	*inbox;
	doment	*domain;
	char	*mailfrom;
	int	socket;
	int	tmprand;
	int	tmpfd;
	int	mode;
	int	crlf[2];
	int	recvhdr;
	int	spam;
	int	score;
	struct
	{
		uint32_t	my_name_is:1,
				from_russia:1,
				my_email:1;
	} wc;
	time_t	activity;

} mailcon;

doment	*domlist;
mailcon *mdb;

/*
 *  some default code for socket flags
 */
static inline void SockFlags(int fd)
{
	fcntl(fd,F_SETFL,O_NONBLOCK | fcntl(fd,F_GETFL));
	fcntl(fd,F_SETFD,FD_CLOEXEC | fcntl(fd,F_GETFD));
}

int SockOpts(void)
{
	struct { int onoff; int linger; } parm;
	int	s;

	if ((s = socket(AF_INET,SOCK_STREAM,0)) < 0)
		return(-1);

	parm.onoff = parm.linger = 0;
	setsockopt(s,SOL_SOCKET,SO_LINGER,(char*)&parm,sizeof(parm));
	parm.onoff++;
	setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,(char*)&parm.onoff,sizeof(int));
	SockFlags(s);
	return(s);
}

int SockListener(int port)
{
	struct	sockaddr_in sai;
	int	s;

	if ((s = SockOpts()) < 0)
		return(-1);
	memset((char*)&sai,0,sizeof(sai));
	sai.sin_family = AF_INET;
	sai.sin_addr.s_addr = INADDR_ANY;
	sai.sin_port = htons(port);
	if ((bind(s,(struct sockaddr*)&sai,sizeof(sai)) < 0) || (listen(s,5) < 0))
	{
		close(s);
		return(-1);
	}
	return(s);
}

struct mailcon * SockAccept(int sock)
{
	struct	sockaddr_in sai;
	int	s;
	socklen_t sz;
	mailcon *new;

	sz = sizeof(sai);
	s = accept(sock,(struct sockaddr*)&sai,&sz);
	if (s >= 0)
	{
		SockFlags(s);
		new = calloc(1,sizeof(struct mailcon));
		new->next = mdb;
		mdb = new;
		new->sai.sin_family = sai.sin_family;
		new->sai.sin_addr.s_addr = sai.sin_addr.s_addr;
		new->sai.sin_port = sai.sin_port;
		new->socket = s;
		new->mode = M_CONTROL;
		new->tmpfd = -1;
		new->activity = now;
		return(new);
	}
	return(NULL);
}

/*
 *  Format text and put it in the logfile
 */
int logout(const char *format, ...)
{
	va_list msg;

	if (logfile == -1)
		return(-1);

	va_start(msg,format);
	vsnprintf(gsockdata,MSGLEN,format,msg);
	va_end(msg);

	return(write(logfile,gsockdata,strlen(gsockdata)));
}

/*
 *  Format text and send to a socket or file descriptor + log
 */
int sockout(int sock, const char *format, ...)
{
	va_list msg;
	int a;

	if (sock == -1)
		return(-1);

	if (logfile >= 0)
	{
		char	s[20];

		sprintf(s,"<%i> ",sock);
		write(logfile,s,strlen(s));
	}

	va_start(msg,format);
	vsnprintf(gsockdata,MSGLEN,format,msg);
	va_end(msg);

	a = strlen(gsockdata);

	if (logfile >= 0)
	{
		write(logfile,gsockdata,a);
	}

	return(write(sock,gsockdata,a));
}

/*
 *  Format text and send to a socket or file descriptor
 */
int fdout(int sock, const char *format, ...)
{
	va_list msg;

	if (sock == -1)
		return(-1);

	va_start(msg,format);
	vsnprintf(gsockdata,MSGLEN,format,msg);
	va_end(msg);

	return(write(sock,gsockdata,strlen(gsockdata)));
}

/*
 *  Read any data waiting on a socket or file descriptor
 *  and return any complete lines to the caller
 *  must be able to read empty lines
 */
char *mailconread(struct mailcon *cur, char *line)
{
	char	*src,*dst,*rdst;
	int	n;

	errno = EAGAIN;

	src = cur->rest;
	dst = line;

	while(*src)
	{
		if ((src[0] == '\r' && src[1] == '\n') || (*src == '\n'))
		{
		got_line:
			/*
			CR ascii 13 = 1101b (*src & 3) evaluates to 1
			LF ascii 10 = 1010b (*src & 3) evaluates to 2
			*/
			cur->crlf[2 - (*src & 3)]++;
			src += 3 - (*src & 3);
			*dst = 0;
			dst = cur->rest;
			while(*src)
				*(dst++) = *(src++);
			*dst = 0;
			return(line);
		}
		*(dst++) = *(src++);
	}
	rdst = src;

	n = read(cur->socket,gsockdata,MSGLEN-2);
	switch(n)
	{
	case 0:
		errno = EPIPE;
	case -1:
		return(NULL);
	}

	gsockdata[n] = 0;
	src = gsockdata;

	while(*src)
	{
		if ((src[0] == '\r' && src[1] == '\n') || (*src == '\n'))
			goto got_line;
		if ((dst - line) >= (MSGLEN-2))
		{
			/*
			 *  line is longer than buffer, let the wheel spin
			 */
			src++;
			continue;
		}
		*(rdst++) = *(dst++) = *(src++);
	}
	*rdst = 0;
	return(NULL);
}
/*
 *  Read any data waiting on a socket or file descriptor
 *  and return any complete lines to the caller
 *  must be able to read empty lines
 */
char *fdread(int fd, char *rest, char *line)
{
	char	*src,*dst,*rdst;
	int	n;

	errno = EAGAIN;

	src = rest;
	dst = line;

	while(*src)
	{
		if ((src[0] == '\r' && src[1] == '\n') || (*src == '\n'))
		{
		got_line:
			src += 3 - (*src & 3);
			*dst = 0;
			dst = rest;
			while(*src)
				*(dst++) = *(src++);
			*dst = 0;
			return(line);
		}
		*(dst++) = *(src++);
	}
	rdst = src;

	n = read(fd,gsockdata,MSGLEN-2);
	switch(n)
	{
	case 0:
		errno = EPIPE;
	case -1:
		return(NULL);
	}

	gsockdata[n] = 0;
	src = gsockdata;

	while(*src)
	{
		if ((src[0] == '\r' && src[1] == '\n') || (*src == '\n'))
			goto got_line;
		if ((dst - line) >= (MSGLEN-2))
		{
			/*
			 *  line is longer than buffer, let the wheel spin
			 */
			src++;
			continue;
		}
		*(rdst++) = *(dst++) = *(src++);
	}
	*rdst = 0;
	return(NULL);
}

void send_statistics(mailcon *cur)
{
	char	*src,*dst,tmptime[100];
	int	lc;

	lc = 0;
	for(dst=tmptime,src=ctime(&uptime);*src&&src<tmptime+99;src++)
	{
		if (*src == '\n')
			break;
		if (*src == ' ' && lc == ' ')
			;
		else
			lc = *dst++ = *src;
	}
	*dst = 0;
	logout("Info request from client\n");
	logfilesize = lseek(logfile,0,SEEK_CUR);
	sockout(cur->socket,"250-uptime since %s (%lu)\r\n",tmptime,uptime);
	sockout(cur->socket,"250-logfile size %lu\r\n",logfilesize);
	sockout(cur->socket,"250-mails: %i received, %i saved, %i bad names, %i relay rejects\r\n",
		receivedmails,savedmails,discardedmails,relayrejects);
	sockout(cur->socket,"250-new inboxes created: %i, connections accepted: %i\r\n250 End of info\r\n",
		newinboxes,connections);
}

void get_from(char *line, mailcon *cur)
{
	char	full[200];
	char	*src,*dst;

	src = line;
	while(*src && *src != ':')
		src++;
	if (*src == ':')
		src++;
	dst = full;
	while(*src && dst < full+190)
	{
		if (*src == '>')
		{
			*dst++ = '>';
			break;
		}
		*dst++ = *src++;
	}
	*dst = 0;
	logout("(%i) From: %s\r\n",cur->socket,full);
	if (*full == '<')
	{
		src = full+1;
		for(dst=full;*dst;dst++);
		while(dst > src)
		{
			if (*dst == '>')
			{
				*dst = 0;
				cur->mailfrom = strdup(src);
			}
			dst--;
		}
	}
	if (cur->mailfrom == NULL)
		cur->mailfrom = dash;
}

doment *ismydomain(char *domain)
{
	doment	*de;

	for(de=domlist;de;de=de->next)
	{
		logout("testing domain: \"%s\"\n",de->dom);
		if (strcasecmp(domain,de->dom) == 0)
		{
			logout("matches domain: \"%s\"\n",de->dom);
			return(de);
		}
	}
	return(NULL);
}

int get_to(char *line, mailcon *cur)
{
	doment	*de;
	char	name[100],domain[100];
	char	fn[200];
	char	*src,*dst;
	int	name_ok = 1;
	int	fd;

	src = line;
	while(*src && *src != '<')
		src++;
	if (*src == '<')
		src++;
	dst = name;
	while(*src && *src != '@' && dst < name+90)
	{
		if (attr[(unsigned char)*src] == 0)
			name_ok = 0;
		*dst++ = *src++;
	}
	*dst = 0;
	if (*src == '@')
		src++;
	dst = domain;
	while(*src && *src != '>' && dst < domain+90)
		*dst++ = *src++;
	*dst = 0;
	logout("(%i) Inbox: %s, Domain: %s\r\n",cur->socket,name,domain);

	if ((fd = open(ADDRLIST,O_WRONLY|O_CREAT|O_APPEND,0600)) >= 0)
	{
		sockout(fd,"%s@%s\n",name,domain);
		close(fd);
	}

	if ((de = ismydomain(domain)) == NULL)
	{
		sockout(cur->socket,"550 eat my shorts\r\n");
		logout("(%i) Not local delivery, discarding\r\n",cur->socket);
		relayrejects++;
		return(0);
	}
	else
	if (name_ok == 0)
	{
		logout("(%i) Username \"%s\" is invalid\r\n",cur->socket,name);
		discardedmails++;
	}
	else
	{
		cur->domain = de;
		cur->tmprand = rand();
		sprintf(fn,"%s.%i.%i",name,getpid(),cur->tmprand);
		logout("(%i) Tempfile %s\r\n",cur->socket,fn);
		fd = open(fn,O_RDWR|O_CREAT|O_TRUNC,0600);
		if (cur->tmpfd >= 0)
		{
			logout("(%i) Duplicate recipient\r\n",cur->socket);
			close(cur->tmpfd);
			if (cur->inbox)
				free(cur->inbox);
		}
		if (fd >= 0)
		{
			fchown(fd,USER_ID,GROUP_ID);
			unlink(fn);
			cur->tmpfd = fd;
			cur->inbox = strdup(name);
			fdout(fd,"From %s %s",(cur->mailfrom) ? cur->mailfrom : dash, ctime(&now));
		}
	}
	return(1);
}

void writedata(int fd, char *data, int n)
{
	char	*end;
	char	*src,*dst;

	src = data;
	dst = data;
	end = data + n;

	while(src < end)
	{
		if (*src == '\r')
		{
			src++;
		}
		else
		if (src == dst)
		{
			dst++;
			src++;
		}
		else
		{
			*dst++ = *src++;
		}
	}
	write(fd,data,(dst - data));
}

int pendingdata(char *rest)
{
	char	*src;

	for(src=rest;*src;src++)
		;
	return(src - rest);
}

int mash(const char *src, const char *pattern)
{
	while(*pattern)
	{
		if ((*pattern == '?') || (*src == *pattern))
			;
		else
			return(*src-*pattern);
		src++;
		pattern++;
	}
	return(0);
}

int wordcount(const char *src, const char *word)
{
	const char *p1,*c1,*c2;
	int	b,count = 0;

	b = toupper(*word);
	p1 = src;
	while(*p1)
	{
		if (toupper(*p1) == b)
		{
			c1 = p1;
			c2 = word;
			while(1)
			{
				if (*c2 == 0)
				{
					if (*c1 == 0 || *c1 == '!' || *c1 == '?' || *c1 == ',' || *c1 == '.' || *c1 == ' ')
						count++;
					break;
				}
				else
				if (*c2 && toupper(*c1) == toupper(*c2))
					;
				else
				if (*c1 == 0)
					return(count);
				else
					break;
				c1++;
				c2++;
			}
		}
		p1++;
	}
	return(count);
}

void parse_input(struct mailcon *cur)
{
	char	*line,data[MSGLEN],*boxname;
	int	fd,n,bc;

flux:
	line = mailconread(cur,data);
	if (line == NULL && errno == EPIPE)
	{
		logout("{%i} socket closed\r\n",cur->socket);
		close(cur->socket);
		cur->socket = -1;
	}
	if (line == NULL)
	{
		if (errno != EAGAIN)
			logout("{%i} socket error: %s\r\n",cur->socket,strerror(errno));
		return;
	}

	if (cur->mode == M_CONTROL)
	{
		cur->activity = now;
		logout("{%i} %s\n",cur->socket,line);
		if (strncasecmp(line,"HELO ",5) == 0)
		{
			sockout(cur->socket,"250 hello\r\n");
			logout("(%i) [%s] pending data after HELO, %i bytes\n",
				cur->socket,inet_ntoa(cur->sai.sin_addr),pendingdata(cur->rest));
		}
		if (strncasecmp(line,"EHLO ",5) == 0)
		{
			sockout(cur->socket,"250-" MYNAME "\r\n250-SIZE 9999999\r\n250 HELP\r\n");
			logout("(%i) [%s] pending data after EHLO, %i bytes\n",
				cur->socket,inet_ntoa(cur->sai.sin_addr),pendingdata(cur->rest));
		}
		if (strncasecmp(line,"MAIL FROM:",10) == 0)
		{
			get_from(line,cur);
			sockout(cur->socket,"250 OK\r\n");
		}
		if (strncasecmp(line,"RCPT TO:",8) == 0)
		{
			if (get_to(line,cur) == 1)
				sockout(cur->socket,"250 OK\r\n");
		}
		if (strcasecmp(line,"DATA") == 0)
		{
			sockout(cur->socket,"354 end data with <CR><LF>.<CR><LF>\r\n");
			cur->mode = M_DATA;
			logout("%i %i %i\n",cur->wc.my_name_is,cur->wc.from_russia,cur->wc.my_email);
		}
		if (strcasecmp(line,"QUIT") == 0)
		{
			sockout(cur->socket,"221 bye\r\n");
			logout("{%i} socket closed\r\n",cur->socket);
			close(cur->socket);
			cur->socket = -1;
			return;
		}
		if (strncasecmp(line,"VRFY ",5) == 0)
		{
			sockout(cur->socket,"252 Cannot VRFY user, but will accept message and attempt delivery\r\n");
		}
		if (strcasecmp(line,"INFO") == 0)
		{
			send_statistics(cur);
		}
	}
	else
	if (cur->mode == M_DATA)
	{
		cur->activity = now;
		logout("{%i} %s\n",cur->socket,line);
		if (mash(line,"Received:") == 0)
		{
			cur->recvhdr++;
		}
		if (mash(line,"L&#246;nen ligger p&#229; ??00-??00 EUR") == 0)
		{
			logout("{%i} Mail is spam\r\n",cur->socket);
			cur->spam = 1;
		}

#define SUBJECT_HI			575
#define SUBJECT_HI_PHPMAILER		576
#define SUBJECT_HI_PHPMAILER_HUGS	577

		if (cur->score == 0 &&
			(strcmp(line,"Subject: hi") == 0 || strcmp(line,"Subject: hey") == 0))
		{
			cur->score = SUBJECT_HI;
		}
		if (cur->score == SUBJECT_HI && mash(line,"X-Mailer: PHPMailer") == 0)
		{
			cur->score = SUBJECT_HI_PHPMAILER;
		}
		if (cur->score == SUBJECT_HI_PHPMAILER &&
			(strcmp(line,"Hugs,") == 0 || strcmp(line,"Kisses,") == 0 || strcmp(line,"Waiting for you,") == 0))
		{
			logout("{%i} Mail is datespam\r\n",cur->socket);
			cur->spam = 1;
		}
		if (wordcount(line,"@rambler.ru") > 0)
		{
			logout("{%i} Mail is ramblerspam\r\n",cur->socket);
			cur->spam = 1;
		}
 		if (wordcount(line,"my name is") > 0)
		{
			logout("(%i) \"my name is\" = 1\r\n",cur->socket);
			cur->wc.my_name_is = 1;
		}
		if (wordcount(line,"from russia") > 0)
		{
			logout("(%i) \"from russia\" = 1\r\n",cur->socket);
			cur->wc.from_russia = 1;
		}
		if (wordcount(line,"my email") > 0)
		{
			logout("(%i) \"my email\" = 1\r\n",cur->socket);
			cur->wc.my_email = 1;
		}
		if (line[0] == '.' && line[1] == 0)
		{
			if (cur->wc.my_name_is == 1 && cur->wc.from_russia == 1 && cur->wc.my_email == 1)
			{
				logout("(%i) Russia spam\r\n",cur->socket);
				cur->spam = 1;
			}
			cur->mode = M_CONTROL;

			sockout(cur->socket,"250 OK: queued as %08x (CR %i, LF %i, Received HDR %i)\r\n",
				cur->tmprand,cur->crlf[0],cur->crlf[1],cur->recvhdr);
			receivedmails++;

			if ((boxname = cur->inbox))
			{
				char	dstfile[1000];

				if (!strcasecmp(boxname,"god"))
					boxname = "obruni";

				if (cur->spam)
				{
					snprintf(dstfile,998,"%s/%s_SPAM",cur->domain->dom,boxname);
					fd = open(dstfile,O_WRONLY|O_CREAT|O_APPEND,0600);
					logout("(%i) Separating spam Inbox %s\r\n",cur->socket,dstfile);
					spam_mails++;
				}
				else
				{
					snprintf(dstfile,998,"%s/%s",cur->domain->dom,boxname);
					if ((fd = open(dstfile,O_WRONLY|O_APPEND,0600)) < 0)
					{
						fd = open(dstfile,O_WRONLY|O_CREAT|O_APPEND,0600);
						logout("(%i) Creating Inbox %s\r\n",cur->socket,dstfile);
						newinboxes++;
					}
					else
					{
						logout("(%i) Appending Inbox %s\r\n",cur->socket,dstfile);
					}
				}
				if (fd >= 0)
				{
					bc = 0;
					lseek(cur->tmpfd,0,SEEK_SET);
					while((n = read(cur->tmpfd,data,MSGLEN)) > 0)
					{
						writedata(fd,data,n);
						bc += n;
					}
					if (n == -1)
					{
						logout("{%i} %s\r\n",cur->socket,strerror(errno));
					}
					close(cur->tmpfd);
					cur->tmpfd = -1;
					logout("{%i} Appended %i bytes to Inbox \"%s\"\r\n",cur->socket,bc,dstfile);
					if (cur->inbox)
					{
						free(cur->inbox);
						cur->inbox = NULL;
					}
					fchown(fd,USER_ID,GROUP_ID);
					close(fd);
					savedmails++;
				}
			}
		}
		else
		{
			fdout(cur->tmpfd,"%s\r\n",line);
		}
	}
	goto flux;
}

int main(int argc, char **argv)
{
	mailcon	*cur,*nxt,*mpt;
	fd_set	rds,wds;
	struct	timeval tv;
	time_t	lastload;
	char	*line;
	int	hisock,inport,n,fd;

	if (argc >= 2)
	{
		sockout(2,"Wordcount 'you': %i\n",wordcount(argv[1],"you"));
		sockout(2,"Wordcount '@rambler.ru': %i\n",wordcount(argv[1],"@rambler.ru"));
		exit(0);
	}

	chdir(CHROOTDIR);
	if (chroot(CHROOTDIR) != 0)
	{
		sockout(2,"Chroot() failed!\n");
		exit(1);
	}

	time(&uptime);
	lastsavedmail = 0;
	logfilesize = 0;
	receivedmails = 0;
	savedmails = 0;
	discardedmails = 0;
	relayrejects = 0;
	newinboxes = 0;
	connections = 0;
	spam_mails = 0;

	fdout(1,"tmail starting %s\n",ctime(&uptime));

	mdb = NULL;
	domlist = NULL;

	close(0);
	close(1);
	close(2);

	switch(fork())
	{
	case 0:
		break;
	default:
	case -1:
		exit(0);
	}
	setsid();

	signal(SIGHUP,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);

	if ((inport = open(MAILPID,O_WRONLY|O_CREAT|O_TRUNC,0640)) >= 0)
	{
		fdout(inport,"%i\n",(int)(getpid()));
		close(inport);
	}

	if ((logfile = open(MAILLOG,O_WRONLY|O_CREAT|O_APPEND,0600)) >= 0)
	{
		logout("tmail started at pid %i\n",(int)(getpid()));
	}

	if ((fd = open(DOMFILE,O_RDONLY)) >= 0)
	{
		doment	*de;
		char	rest[MSGLEN],txt[MSGLEN];

		logout("reading domain file\n");
		*rest = 0;
		*txt = 0;
		while((line = fdread(fd,rest,txt)) != NULL)
		{
			if (strlen(line) >= 4)
			{
				logout("maildomain: \"%s\"\n",line);
				de = calloc(1,sizeof(struct doment)+strlen(line)+8);
				de->next = domlist;
				strcpy(de->dom,line);
				domlist = de;
			}
		}
		close(fd);
	}

	while(1)
	{
		inport = SockListener(25);
		if (inport >= 0)
		{
			logout(":%i: Listener on port 25\r\n",inport);
			break;
		}
		logout(":: bind failed, sleeping for 30 seconds before retrying\r\n");
		sleep(30);
	}

	line = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.";
	while(*line)
	{
		attr[(unsigned char)*line] = 1;
		line++;
	}

	time(&now);
	lastload = 0;

mainloop:

	FD_ZERO(&rds);
	FD_ZERO(&wds);
	hisock = -1;

	tv.tv_sec = ((lastload+60) > now) ? ((lastload+60) - now) : 1;
	tv.tv_usec = 0;

	for(cur=mdb;cur;cur=cur->next)
	{
		if (cur->socket > hisock) hisock = cur->socket;
		if (cur->socket >= 0) FD_SET(cur->socket,&rds);
	}

	if (inport > hisock) hisock = inport;
	if (inport >= 0) FD_SET(inport,&rds);

	if ((select(hisock+1,&rds,&wds,0,&tv) == -1) && (errno == EINTR))
		goto mainloop;

	time(&now);

	if ((inport != -1) && FD_ISSET(inport,&rds))
	{
		if ((cur = SockAccept(inport)))
		{
			n = cur->socket;
			logout("{%i} accepted new connection [%s:%i]\r\n",n,
				inet_ntoa(cur->sai.sin_addr),ntohs(cur->sai.sin_port));
			sockout(n,"220 " MYNAME " tmail\r\n");
			connections++;
		}
	}

	cur = mdb;
	while(1)
	{
		if (cur == NULL)
			break;

		nxt = cur->next;

		if ((now - cur->activity) > 660)
		{
			logout("<%i> idle timeout\r\n",cur->socket);
			close(cur->socket);
			cur->socket = -1;
		}

		if (cur->socket == -1)
		{
			if (cur == mdb)
			{
				mdb = nxt;
			}
			else
			for(mpt=mdb;mpt;mpt=mpt->next)
			{
				if (mpt->next == cur)
				{
					mpt->next = nxt;
					break;
				}
			}
			if (cur->inbox)
			{
				free(cur->inbox);
			}
			if (cur->mailfrom && cur->mailfrom != dash)
			{
				free(cur->mailfrom);
			}
			if (cur->tmpfd >= 0)
			{
				close(cur->tmpfd);
			}
			free(cur);
		}
		cur = nxt;
	}

	for(cur=mdb;cur;cur=cur->next)
	{
		if ((cur->socket >= 0) && FD_ISSET(cur->socket,&rds))
		{
			parse_input(cur);
		}
	}

	goto mainloop;

	return(0);
}
