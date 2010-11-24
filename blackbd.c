#include <stdlib.h>
#include <stdio.h>
#include <event.h>
#include <evhttp.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

// NOTES:
// requires latest stable libevent 1.4.6  http://monkey.org/~provos/libevent/
// python sample code at the bottom
//

// TODO: 
// 3 - optional gzip compression
// 4 - logging
// 5 - some magical atom feed? 
// 6 - perhaps some test would be nice 

#define BLACKBD_VERSION "Blackbd 0.1"

typedef struct _kv_pair_list_t { 
	char *key;	
	char *value;
	struct _kv_pair_list_t *next;
} kv_pair_list_t;

typedef struct _board_posts_t {
	int queue_size;
	kv_pair_list_t **entries;
	int offset;
	char *json_output;
	int json_output_len;
	char json_output_len_string[128];
	struct tm updated_time;
	char updated_string[128];
	const char *post_secret;
	unsigned int get_count;
	unsigned int post_count;
} board_posts_t;


/** used for basic auth **/
/* must free the memory returned - passing in -1 will cause the function to treat the incomng as a null terminated string */
static char *base64_encode(const unsigned char *insrc, int inlen) {
	inlen = inlen >= 0 ? inlen	: strlen( (const char*)insrc);
	unsigned int outlen = (inlen + 2) / 3 * 4;
	static char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	unsigned int thirds = inlen / 3;
	unsigned int i;
	char *out = malloc(outlen +1);
	char *rout = out;
	memset(out,0,outlen+1);

	for (i = 0; i < thirds; i++, out += 4, insrc += 3) {
		out[0] = lookup[insrc[0] >> 2];
		out[1] = lookup[((insrc[0] & 0x3) << 4) | (insrc[1] >> 4)];
		out[2] = lookup[((insrc[1] & 0xf) << 2) | (insrc[2] >> 6)];
		out[3] = lookup[insrc[2] & 0x3f];
	}
	inlen -= (3 * thirds);
	if (inlen > 0) {
		unsigned char buf[3];
		buf[0] = buf[1] = buf[2] = 0;
		switch (inlen) {
			case 2:
				buf[1] = insrc[1];
			case 1:
				buf[0] = insrc[0];
		}
		out[0] = lookup[buf[0] >> 2];
		out[1] = lookup[((buf[0] & 0x3) << 4) | (buf[1] >> 4)];
		out[3] = '=';
		if (inlen == 1) {
				out[2] = '=';
		} else {
				out[2] = lookup[(buf[1] & 0xf) << 2];
		}
		out += 4;
	}
	*out = '\0';
	return rout;
}

static char * json_string(const char *in) { 
	//length is *2 for each character if escape + 1 for terminator and +2 for leading/trailing "
	char *out = calloc(((strlen(in)*2) +3),sizeof(char));  
	const char *p = in;
	char *op = out;
	while(*p !='\0') { 
		switch(*p) { 
			case '\n': *op++ = '\\'; *op++='n';break;
			case '\r': *op++ = '\\'; *op++='r';break;
			case '\t': *op++ = '\\'; *op++='t';break;
			case '\b': *op++ = '\\'; *op++='b';break;
			case '\f': *op++ = '\\'; *op++='f';break;
			case '\\': *op++ = '\\'; *op++='\\';break;
			case '/': *op++ = '\\'; *op++='/';break;
			case '"': *op++ = '\\'; *op++='"';break;
			default:
					*op++= *p;
		}
		p++;
	}
	return out;
}

static void dump_entry_json(struct evbuffer *buffer, kv_pair_list_t *entry) {
	char *hold = NULL;
	evbuffer_add_printf(buffer,"{");
	while(entry != NULL && entry->key !=NULL && entry->value !=NULL) { 
		evbuffer_add_printf(buffer,"\"%s\":\"%s\"%s", entry->key, 
				hold = json_string(entry->value) , (entry->next!=NULL && entry->next->key !=NULL && entry->next->value !=NULL  ? "," : "")
				);
		free(hold); 
		hold = NULL;
		entry = entry->next;
	}
	evbuffer_add_printf(buffer,"}");
}

static void free_entry(kv_pair_list_t *entry) { 
	kv_pair_list_t *old;
	while(entry) {   
		free(entry->key);
		free(entry->value);
		old = entry;
		entry= entry->next;
		free(old);
	}
}
static kv_pair_list_t *  post_parse(unsigned char *data, unsigned int data_len) { 
	char *post_data = calloc(data_len+1,sizeof(char));
	memcpy(post_data,data,data_len);
	char *fmarker = NULL;
	char *fsplit  = strtok_r(post_data,"&",&fmarker);
	kv_pair_list_t *head = NULL;
	kv_pair_list_t *last = NULL;
	while(fsplit!=NULL) { 
		char *vmarker = NULL;
		char *key = strtok_r(fsplit,"=",&vmarker);
		char *value = strtok_r(NULL,"=",&vmarker);
		value = value ? value : "";
		value = evhttp_decode_uri(value);
		char *p = value;
		while(*p!='\0') { if (*p=='+') *p = ' '; p++;}
		kv_pair_list_t *entry = malloc(sizeof(kv_pair_list_t));
		entry->key = strdup(key); 
		entry->value = value; //don't copy since you get a new memory from decode_uri
		entry->next = NULL;
		if(head == NULL){ 
			head = entry;
		}
		if(last != NULL) {  
			last->next = entry;
		}
		last = entry;
		fsplit = strtok_r(NULL,"&",&fmarker);
	}
	free(post_data);
	return head;
}

void generate_json(board_posts_t *board) { 
	struct evbuffer *buffer = evbuffer_new();
	evbuffer_add_printf(buffer,"[");
	if (board->entries[board->offset] != NULL) { 
		int count = 0;
		int i;
		for(i = board->offset; i> -1  && board->entries[i] != NULL; i--) { 
				if(count > 0) { evbuffer_add_printf(buffer,","); } 
				dump_entry_json(buffer,board->entries[i]);
				count++;
		}
		for(i = board->queue_size - 1 ; i> board->offset && board->entries[i] !=NULL; i--) { 
				if(count > 0) { evbuffer_add_printf(buffer,","); } 
				dump_entry_json(buffer,board->entries[i]);
				count++;
		}
	}
	evbuffer_add_printf(buffer,"]");
	free(board->json_output);
	board->json_output = malloc((board->json_output_len = EVBUFFER_LENGTH(buffer)));
	memcpy(board->json_output,EVBUFFER_DATA(buffer),board->json_output_len);
	snprintf(board->json_output_len_string,sizeof(board->json_output_len_string),"%d",board->json_output_len);
	evbuffer_free(buffer);
}

void bboard_POST(struct evhttp_request *request, void *_board) { 
	board_posts_t* board = (board_posts_t*)_board;
	board->post_count++;
	const char *req_secret = NULL;

	/** security hole - attacker could post a long combination of characters since we are not parsing the header **/
	if(board->post_secret && 
			((req_secret =evhttp_find_header(request->input_headers,"Authorization"))==NULL || 
			strstr(req_secret,board->post_secret)==NULL) ) { 
		struct evbuffer *buffer = evbuffer_new();
		printf("post_secret = %s | header = %s\n",board->post_secret,req_secret ? req_secret : "(null)");
		evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
		evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
		evhttp_add_header(request->output_headers, "WWW-Authenticate", "Basic realm=\"Blackbd Server POSTING\"");
		evhttp_add_header(request->output_headers, "Connection", "close");
		evhttp_send_reply(request,401,"UNAUTHORIZED",buffer);
		evbuffer_free(buffer);
		return;
	}
	kv_pair_list_t *entry = post_parse(EVBUFFER_DATA(request->input_buffer),EVBUFFER_LENGTH(request->input_buffer));

	if(entry) { 
		if(board->entries[board->offset] == NULL) { 
			board->entries[board->offset] = entry;
		} else { 
			board->offset++;
			if(board->offset > board->queue_size -1 ) { board->offset = 0; }
			if(board->entries[board->offset])
				free_entry(board->entries[board->offset]);
			board->entries[board->offset] =  entry;
		}
		generate_json(board);
		time_t now = time(NULL);
		gmtime_r(&now,&(board->updated_time));
		strftime(board->updated_string,sizeof(board->updated_string)-1,
				"%a, %d %b %Y %H:%M:%S GMT",&(board->updated_time));

		struct evbuffer *buffer = evbuffer_new();
		evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
		evhttp_add_header(request->output_headers, "Date", board->updated_string);
		evhttp_add_header(request->output_headers, "Last-Modified", board->updated_string);
		evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
		evhttp_add_header(request->output_headers, "Cache-control", "max-age=10");
		evhttp_add_header(request->output_headers, "Content-Length", board->json_output_len_string);
		evhttp_add_header(request->output_headers, "Connection", "close");
		evbuffer_add(buffer,board->json_output,board->json_output_len);
		evhttp_send_reply(request,HTTP_OK,"OK",buffer);
		evbuffer_free(buffer);
	} else { 
		char current_time[128];
		time_t now = time(NULL);
		struct tm current; 
		gmtime_r(&now,&current);
		strftime(current_time,sizeof(current_time)-1,
				"%a, %d %b %Y %H:%M:%S GMT",&current);
		struct evbuffer *buffer = evbuffer_new();
		evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
		evhttp_add_header(request->output_headers, "Date", current_time);
		evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
		evhttp_add_header(request->output_headers, "Connection", "close");
		evhttp_send_reply(request,HTTP_BADREQUEST,"Bad Request",buffer);
		evbuffer_free(buffer);
	}
}

void bboard_GET(struct evhttp_request *request, void *_board) { 
	board_posts_t* board = (board_posts_t*)_board;
	board->get_count++;
	struct evbuffer *buffer = evbuffer_new();
	char current_time[128];

	time_t now = time(NULL);
	struct tm current; 
	gmtime_r(&now,&current);
	strftime(current_time,sizeof(current_time)-1,
				"%a, %d %b %Y %H:%M:%S GMT",&current);

	const char *ifmod = evhttp_find_header(request->input_headers,"If-Modified-Since");
	const char *connection = evhttp_find_header(request->input_headers,"Connection");

	if (ifmod && strcmp(ifmod,board->updated_string) == 0){
		printf("%s = %s\n",ifmod,board->updated_string);
		evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
		evhttp_add_header(request->output_headers, "Date", current_time);
		evhttp_add_header(request->output_headers, "Last-Modified", board->updated_string);
		evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
		evhttp_add_header(request->output_headers, "Content-Length", "0");
		evhttp_add_header(request->output_headers, "Cache-control", "max-age=10");
		if(connection  == NULL ||  strcasecmp(connection,"keep-alive") != 0)  
			evhttp_add_header(request->output_headers, "Connection", "close");
		evhttp_send_reply(request,HTTP_NOTMODIFIED,"Not Modified",buffer);
	} else { 
		char *callback = NULL;
		char *offset = NULL;

		if((offset = strchr(request->uri,'?') ) !=NULL) { 
			kv_pair_list_t *kvp =  post_parse((unsigned char*)(offset+1), strlen(offset+1));
			kv_pair_list_t *head = kvp;
			while(kvp!=NULL) { 	
				if(strcmp(kvp->key,"callback")==0){
					callback = strdup(kvp->value);
					break;
				}
				kvp  = kvp->next;
		 	}	
			free_entry(head);
		}
		evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
		evhttp_add_header(request->output_headers, "Date", current_time);
		evhttp_add_header(request->output_headers, "Last-Modified", board->updated_string);
		evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
		evhttp_add_header(request->output_headers, "Cache-control", "max-age=10");
		if(connection  == NULL ||  strcasecmp(connection,"keep-alive") != 0)  
			evhttp_add_header(request->output_headers, "Connection", "close");
		if(callback) evbuffer_add_printf(buffer,"%s(",callback);

		evbuffer_add(buffer,board->json_output,board->json_output_len);

		if(callback) {
			char buffer_len[128];
			evbuffer_add_printf(buffer,");");
			snprintf(buffer_len,sizeof(buffer_len),"%ld",EVBUFFER_LENGTH(buffer));	
			evhttp_add_header(request->output_headers, "Content-Length", buffer_len);
		} else {
			evhttp_add_header(request->output_headers, "Content-Length", board->json_output_len_string);
		}
		evhttp_send_reply(request,HTTP_OK,"OK",buffer);
		free(callback);
	}
	evbuffer_free(buffer);
}

void bboard_callback(struct evhttp_request *request, void *_board){
	if(request->type == EVHTTP_REQ_POST) { 
		bboard_POST(request,_board);
  } else { 
		bboard_GET(request,_board);
	}
}

//since i don't do logging
void bboard_callback_stats(struct evhttp_request *request, void *_board) { 
	board_posts_t* board = (board_posts_t*)_board;
	struct evbuffer *buffer = evbuffer_new();
	char current_time[128];
	char content_length[128];

	time_t now = time(NULL);
	struct tm current; 
	gmtime_r(&now,&current);
	strftime(current_time,sizeof(current_time)-1,
				"%a, %d %b %Y %H:%M:%S GMT",&(board->updated_time));
	evbuffer_add_printf(buffer,"{\"GET\" : %d , \"POST\" : %d }",board->get_count,board->post_count);
	snprintf(content_length,sizeof(content_length),"%ld",EVBUFFER_LENGTH(buffer));
	evhttp_add_header(request->output_headers, "Server", BLACKBD_VERSION);
	evhttp_add_header(request->output_headers, "Date", current_time);
	evhttp_add_header(request->output_headers, "Content-Type", "text/plain");
	evhttp_add_header(request->output_headers, "Content-Length", content_length);
	evhttp_add_header(request->output_headers, "Connection", "close");
	evhttp_send_reply(request,HTTP_OK,"OK",buffer);
	evbuffer_free(buffer);

}

void launch_bboard(int port,char *uri,const char *secret,int queue_size) { 
  board_posts_t board;
	board.queue_size = queue_size;
	board.entries = malloc(sizeof(kv_pair_list_t*) * board.queue_size);
	memset(board.entries,0,sizeof(kv_pair_list_t*) * board.queue_size);
	board.post_count = board.get_count = 0;
	board.offset = 0;
	board.json_output = NULL;
	board.json_output_len = 0;
	snprintf(board.json_output_len_string,sizeof(board.json_output_len_string),"%d",board.json_output_len);
	board.updated_string[0] = '\0';
	board.post_secret = secret;
	//set the default update time to start time
	time_t now = time(NULL);
	gmtime_r(&now,&(board.updated_time));
	strftime(board.updated_string,sizeof(board.updated_string)-1,
				"%a, %d %b %Y %H:%M:%S GMT",&(board.updated_time));

	struct event_base *base = event_init();
	struct evhttp *http = evhttp_new(base);
	evhttp_set_cb (http, uri, bboard_callback, &board);
	evhttp_set_cb (http,"/stats", bboard_callback_stats,&board);
	evhttp_bind_socket(http,"0.0.0.0",port);
	event_dispatch();
}

static void print_usage() { 
	printf("Usage: blackbd -p port -u /uri -q queue-size -s username:password -d[ebug] -h[elp]\n");
}
int main(int argc, char **argv) { 
	int opt;
	int debug = 0;
	unsigned int port = 0;
	unsigned int queue_size = 20;
	char *uri = NULL;
	char *secret =NULL;

	while((opt = getopt(argc,argv,"p:u:q:s:dh?")) !=EOF) { 
		switch(opt){ 
			case 'p': port = atoi(optarg); break;
			case 'u': uri = strdup(optarg); break;
			case 's': secret= base64_encode((const unsigned char *)optarg,-1); break;
			case 'q': queue_size = atoi(optarg); break;
			case 'd': debug = 1; break;
			case 'v': printf("Version: %s\n",BLACKBD_VERSION);
			case 'h':
			case '?':
			default:
					print_usage();
					exit(1);
		}
	}
	if(port == 0)  {
		printf("No port defined\n");
		print_usage(); 
		exit(1);
	}
	if(uri == NULL) {
		printf("No uri defined\n");
		print_usage(); 
		exit(1);
	}

	if(secret == NULL) {
		printf("No POSTing secret defined - anybody will be able to post\n");
	}

	if(!debug) { 
		if(fork()) { 
			return 0;
		} else { 
			close(0);close(1);close(2);
		}
	}
	//ignore signals on SIGPIPE
	struct sigaction act;
	act.sa_handler = SIG_IGN;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction (SIGPIPE, &act, NULL);

	launch_bboard(port,uri,secret,queue_size);	
	return 0;
}

/*** PYTHON ****/ 
/**
import urllib,urllib2,base64

#get some data to feed 
data = eval(urllib2.urlopen('http://foox/view/people/52396025/1/feed.js').read().replace('\\/','/'))

#post the data to the "live" service
#includes basic auth value of "derek:derek"
#revserse the list so oldest first

[urllib2.urlopen(urllib2.Request('http://foox/svc/timespeople/live',urllib.urlencode(x),{'Authorization':'Basic %s' %  base64.b64encode('derek:derek')})).read()
 for x in data[::-1]]

#pull back the data
print eval(urllib2.urlopen('http://foox/svc/timespeople/live').read().replace('\\/','/'))

**/
