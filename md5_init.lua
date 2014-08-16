local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_typeof  = ffi.typeof
local ffi_C = ffi.C

ffi.cdef[[
    typedef unsigned long MD5_LONG;
    typedef struct MD5state_st {
        MD5_LONG A,B,C,D;
        MD5_LONG Nl,Nh;
        MD5_LONG data[16];
        unsigned int num;
    } MD5_CTX;

    int MD5_Init(MD5_CTX *c);
    int MD5_Update(MD5_CTX *c, const void *data, size_t len);
    int MD5_Final(unsigned char *md, MD5_CTX *c);
    unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
    void MD5_Transform(MD5_CTX *c, const unsigned char *b);
]]

local md5_ctx_type = ffi_typeof('MD5_CTX')


function md5(path)
    local fp = io.open(path, 'r')
    local md5_ctx = ffi_new(md5_ctx_type)
    local md5_str = ffi_new('unsigned char[?]', 16)
    local md5_str1 = ''

    ffi_C.MD5_Init(md5_ctx)

    while true do
        buffer = fp:read(1024)
        if not buffer then
            break
        else
            ffi_C.MD5_Update(md5_ctx, buffer, #buffer)
        end
    end
    fp:close()

    ffi_C.MD5_Final(md5_str, md5_ctx)
    
    for i=0, 15 do
        local tmp = string.format("%x", tostring(md5_str[i]))
        md5_str1 = md5_str1 .. tmp
    end

    return md5_str1
end
