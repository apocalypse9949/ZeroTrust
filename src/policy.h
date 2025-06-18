#ifndef POLICY_H
#define POLICY_H

void check_policy(const u_char *packet, int len);
void block_ip(const char *ip);
void log_event(const char *event_type, const char *description);
void add_known_ip(const char *ip);
int is_known_ip(const char *ip);

#endif
