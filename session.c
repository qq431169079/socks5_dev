
#include "session.h"
#include "defs.h"
#include "resolve.h"

session_t *create_session()
{
    session_t *session = lmalloc(sizeof(session_t));
    //初始化socks5识别
    session->session_fields.state = S5_METHOD_IDENTIFICATION;
    //初始化请求类型
    session->session_fields.type = SESSION_TYPE_UNKNOWN;
    return session;
}

void close_session(session_t *session)
{
    if (session->session_fields.state == S5_CLOSING)
    {
        return;
    }
    //设置关闭
    session->session_fields.state = S5_CLOSING;
    //TODO
}
