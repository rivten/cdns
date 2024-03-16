#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authorities;
    uint16_t num_additionals;
};

struct dns_question {
   size_t bytes_len;
   uint8_t* bytes; 
   uint16_t type;
   uint16_t class;
};

uint8_t* header_to_bytes(struct dns_header header, size_t* buflen) {
    *buflen = sizeof(struct dns_header);
    uint8_t* buf = malloc(*buflen);
    uint16_t* b = (uint16_t*)buf;
    *b++ = htons(header.id);
    *b++ = htons(header.flags);
    *b++ = htons(header.num_questions);
    *b++ = htons(header.num_answers);
    *b++ = htons(header.num_authorities);
    *b++ = htons(header.num_additionals);
    return buf;
}

uint8_t* question_to_bytes(struct dns_question question, size_t* buflen) {
    *buflen = question.bytes_len + 2 * sizeof(uint32_t);
    uint8_t* buf = malloc(*buflen);
    memcpy(buf, question.bytes, question.bytes_len);
    uint16_t* b = (uint16_t*)(buf + question.bytes_len);
    *b++ = htons(question.type);
    *b++ = htons(question.class);
    return buf;
}

uint8_t* encode_dns_name(const char* domain_name, size_t* buflen) {
#define MAX_BUF_SIZE 1024
    uint8_t* buf = malloc(MAX_BUF_SIZE);
    *buflen = 0;
    size_t end = 0;
    size_t start = 0;
    for (const char* c = domain_name; *c != 0; ++c) {
        if (*c == '.') {
            assert(end - start < 0xff);
            assert(*buflen + 1 + end - start < MAX_BUF_SIZE);

            buf[*buflen] = end - start;
            memcpy(buf + *buflen + 1, domain_name + start, end - start);
            *buflen += 1 + end - start;

            start = end + 1;

        }
        ++end;
    }
    if (end > start) {
        assert(end - start < 0xff);
        assert(*buflen + 1 + end - start < MAX_BUF_SIZE);

        buf[*buflen] = end - start;
        memcpy(buf + *buflen + 1, domain_name + start, end - start);
        *buflen += 1 + end - start;

        start = end + 1;
    }
    return buf;
}

enum type {
    TYPE_A = 1,
};

enum class {
    CLASS_IN = 1,
};

#define DNSFLAGS_RECURSION_DESIRED (1<<8)

uint8_t* build_query(const char* domain_name, uint16_t record_type, size_t* outlen) {
    size_t name_bytes_len;
    uint8_t* name_bytes = encode_dns_name(domain_name, &name_bytes_len);

    const uint16_t id = rand() & 0xffff;
    const struct dns_header header = {
        .id = id,
        .flags = DNSFLAGS_RECURSION_DESIRED,
        .num_questions = 1,
        .num_answers = 0,
        .num_authorities = 0,
        .num_additionals = 0,
    };
    
    const struct dns_question question = {
        .bytes_len = name_bytes_len,
        .bytes = name_bytes,
        .type = record_type,
        .class = CLASS_IN,
    };

    size_t header_bytes_len;
    uint8_t* header_bytes = header_to_bytes(header, &header_bytes_len);

    size_t question_bytes_len;
    uint8_t* question_bytes = question_to_bytes(question, &question_bytes_len);

    *outlen = header_bytes_len + question_bytes_len;
    uint8_t* query = malloc(*outlen);
    memcpy(query, header_bytes, header_bytes_len);
    memcpy(query + header_bytes_len, question_bytes, question_bytes_len);

    free(question_bytes);
    free(header_bytes);
    free(name_bytes);

    return query;
}

int main() {
    srand(time(NULL));
    size_t blen;
    //struct dns_header header = {
    //    .id = 0x1314,
    //    .flags = 0,
    //    .num_questions = 1,
    //    .num_answers = 0,
    //    .num_authorities = 0,
    //    .num_additionals = 0,
    //};
    //uint8_t* header_bytes = header_to_bytes(header,&blen);
    //for (size_t i = 0; i < blen; ++i) {
    //    printf("\\x%02x", header_bytes[i]);
    //}
    //printf("\n");
    //free(header_bytes);


    //uint8_t* buf = encode_dns_name("google.com", &blen);
    //for (size_t i = 0; i < blen; ++i) {
    //    printf("\\x%02x", buf[i]);
    //}
    //printf("\n");
    //free(buf);


    blen = 0;
    uint8_t* buf = build_query("google.com", TYPE_A, &blen);
    for (size_t i = 0; i < blen; ++i) {
        printf("\\x%02x", buf[i]);
    }
    printf("\n");

    struct addrinfo hints;
    struct addrinfo *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo("8.8.8.8", "53", &hints, &servinfo);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sock >= 0);

    int numbytes = sendto(sock, buf, blen, 0, servinfo->ai_addr, servinfo->ai_addrlen);
    assert(numbytes > 0);

    uint8_t recvbuf[1024];
    socklen_t fromlen;
    struct sockaddr from;
    int recvbytes = recvfrom(sock, recvbuf, 1023, 0, &from, &fromlen);
    assert(recvbytes > 0);
    recvbuf[recvbytes] = 0;

    for (int i = 0; i < recvbytes; ++i) {
        printf("\\x%02x", recvbuf[i]);
    }
    printf("\n");
    


    freeaddrinfo(servinfo);

    free(buf);


    return 0;
}
