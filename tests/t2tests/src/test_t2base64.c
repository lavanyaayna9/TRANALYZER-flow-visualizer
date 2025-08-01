#include "test_t2base64.h"
#include "t2tests.h"      // for T2_ASSERT_CONST_STR_EQ
#include "t2base64.h"     // for t2_base64_encode_alloc


bool test_t2_base64_encode() {
    struct {
        const char * const input;
        const char * const expected;
    } data[] = {
        { ""      , ""         },
        { "f"     , "Zg=="     },
        { "fo"    , "Zm8="     },
        { "foo"   , "Zm9v"     },
        { "foob"  , "Zm9vYg==" },
        { "fooba" , "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
        { NULL    , NULL       }
    };

    for (uint_fast32_t i = 0; data[i].input; i++) {
        char * const b64 = t2_base64_encode_alloc(data[i].input, strlen(data[i].input));
        T2_ASSERT_CONST_STR_EQ(b64, data[i].expected);
        free(b64);
    }

    return true;
}
