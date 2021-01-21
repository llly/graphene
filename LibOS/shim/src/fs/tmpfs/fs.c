/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for implementation of 'str' filesystem.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "stat.h"

struct shim_tmpfs_data {
    struct shim_str_data str_data;
    struct shim_lock lock;
    struct atomic_int version;
    bool queried;
    enum shim_file_type type;
    mode_t mode;
    struct atomic_int size;
    unsigned long atime;
    unsigned long mtime;
    unsigned long ctime;
    unsigned long nlink;
};

static int tmpfs_mount(const char* uri, void** mount_data) {
    //if (uri)
    //    return -EINVAL;
    return 0;
}

static int tmpfs_unmount(void* mount_data) {
    return 0;
}

/* simply just create data, sometimes it is individually called when the
   handle is not linked to a dentry */
static struct shim_tmpfs_data* __create_data(void) {
    struct shim_tmpfs_data* data = calloc(1, sizeof(struct shim_tmpfs_data));
    if (!data)
        return NULL;

    memset(data, 0, sizeof(struct shim_tmpfs_data));

    if (!create_lock(&data->lock)) {
        free(data);
        return NULL;
    }
    return data;
}

static void __destroy_data(struct shim_tmpfs_data* data) {
    destroy_lock(&data->lock);
    free(data);
}

/* create a data in the dentry and compose it's uri. dent->lock needs to
   be held */
static int create_data(struct shim_dentry* dent) {
    assert(locked(&dent->lock));

    if (dent->data)
        return 0;

    struct shim_tmpfs_data* data = __create_data();
    if (!data)
        return -ENOMEM;

    
    data->type = FILE_UNKNOWN;
    data->mode = 0;
    //struct atomic_int size;

    uint64_t time = DkSystemTimeQuery();
    if (time == (uint64_t)-1)
        time = 0;
    data->atime = time / 1000000;
    data->mtime = data->atime;
    data->ctime = data->atime;
    data ->nlink = 1;
    
    dent->data = data;
    return 0;
}

static inline int try_create_data(struct shim_dentry* dent,
                                  struct shim_tmpfs_data** dataptr) {
    struct shim_tmpfs_data* data = (struct shim_tmpfs_data*)(dent)->data;

    if (!data) {
        lock(&dent->lock);
        int ret = create_data(dent);
        data = (struct shim_tmpfs_data*)(dent)->data;
        unlock(&dent->lock);
        if (ret < 0) {
            return ret;
        }
    }

    *dataptr = data;
    return 0;
}

static int tmpfs_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    int ret = 0;
    struct shim_tmpfs_data* data;
    if ((ret = try_create_data(dent, &data)) < 0)
        return ret;

    uint64_t time = DkSystemTimeQuery();
    if (time == (uint64_t)-1)
        time = 0;
    
    lock(&data->lock);
    if (data->type == FILE_UNKNOWN)
    {
        if (flags & O_CREAT)
        {
            data->type = FILE_REGULAR;
            dent->type = S_IFREG;
            
            //always keep handle for tmpfs until unlink
            get_handle(hdl);
        }
        else
        {
            return -ENOENT;
        }
    }
    
    REF_INC(data->str_data.ref_count);

    hdl->dentry = dent;
    hdl->type     = TYPE_STR;
    hdl->flags    = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.str.data = &data->str_data;
    if (flags & O_APPEND)
        hdl->info.str.ptr = data->str_data.str + data->str_data.len;
    else
        hdl->info.str.ptr = data->str_data.str;
    
    
    data->atime = time / 1000000;

    unlock(&data->lock);

    return 0;
}

static int tmpfs_dput(struct shim_dentry* dent) {
    //struct shim_tmpfs_data* tmpfs_data = dent->data;
    //struct shim_str_data* data = &tmpfs_data->str_data;

    return str_dput(dent);
}

static int tmpfs_flush(struct shim_handle* hdl) {
    return str_flush(hdl);
}

static int tmpfs_close(struct shim_handle* hdl) {
    if (hdl->flags & (O_WRONLY | O_RDWR)) {
        int ret = tmpfs_flush(hdl);

        if (ret < 0)
            return ret;
    }

    tmpfs_dput(hdl->dentry);
    return 0;
}

static ssize_t tmpfs_read(struct shim_handle* hdl, void* buf, size_t count) {
    assert(hdl->dentry);
    if (!(hdl->acc_mode & MAY_READ)) {
        return -EBADF;
    }

    struct shim_tmpfs_data* tmpfs_data = hdl->dentry->data;
    if (!tmpfs_data) {
        return -ENOENT;
    }
    if (tmpfs_data->type != FILE_REGULAR) {
        return -EISDIR;
    }
 
    ssize_t ret = str_read(hdl, buf, count);
    return  ret == -EACCES? 0 : ret;
}

static ssize_t tmpfs_write(struct shim_handle* hdl, const void* buf, size_t count) {
    assert(hdl->dentry);
    if (!(hdl->acc_mode & MAY_WRITE)) {
        return -EBADF;
    }

    struct shim_tmpfs_data* tmpfs_data = hdl->dentry->data;
    if (!tmpfs_data) {
        return -ENOENT;
    }
    if (tmpfs_data->type != FILE_REGULAR) {
        return -EISDIR;
    }

    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    if (!data->str || strhdl->ptr + count > data->str + data->buf_size) {
        int newlen = 0;

        if (data->str) {
            newlen = data->buf_size * 2;

            while (strhdl->ptr + count > data->str + newlen) {
                newlen *= 2;
            }
        } else {
            /* This line is diffrent from strfs*/
            newlen = strhdl->ptr + count - data->str;
        }

        char* newbuf = malloc(newlen);
        if (!newbuf)
            return -ENOMEM;

        /* This line is diffrent from strfs*/
        memset(newbuf, 0, newlen);
        if (data->str) {
            memcpy(newbuf, data->str, data->len);
            free(data->str);
        }

        strhdl->ptr    = newbuf + (strhdl->ptr - data->str);
        data->str      = newbuf;
        data->buf_size = newlen;
    }

    memcpy(strhdl->ptr, buf, count);

    strhdl->ptr += count;
    data->dirty = true;
    if (strhdl->ptr >= data->str + data->len)
        data->len = strhdl->ptr - data->str;

    uint64_t time = DkSystemTimeQuery();
    if (time == (uint64_t)-1)
        time = 0;
    
    tmpfs_data->atime = time / 1000000;
    tmpfs_data->mtime = tmpfs_data->atime;
    tmpfs_data->ctime = tmpfs_data->atime;

    return count;
}


static int tmpfs_mmap(struct shim_handle* hdl, void** addr, size_t size, int prot, int flags,
                       off_t offset) {
    int ret;
    void* mem         = *addr;

#if MAP_FILE == 0
    if (flags & MAP_ANONYMOUS)
#else
    if (!(flags & MAP_FILE))
#endif
        return -EINVAL;

    assert(hdl->dentry);
    struct shim_tmpfs_data* data;
    if ((ret = try_create_data(hdl->dentry, &data)) < 0)
        return ret;
    if (data->str_data.len < size + offset )
    {
        debug("mmap beyond tmpfs file end\n");
        //return -EINVAL;
    }
    
    //TODO mmap EPC addr  `data->str_data.str + offset` to EPC addr `*addr`
    //*addr = data->str_data.str + offset;
    //return 0;
    return ENOSYS;

}
static off_t tmpfs_seek(struct shim_handle* hdl, off_t offset, int whence) {
    struct shim_str_handle* strhdl = &hdl->info.str;

    assert(hdl->dentry);
    assert(strhdl->data);

    struct shim_str_data* data = strhdl->data;

    switch (whence) {
        case SEEK_SET:
            if (offset < 0)
                return -EINVAL;
            strhdl->ptr = data->str + offset;
            break;

        case SEEK_CUR:
                strhdl->ptr += offset;
            break;

        case SEEK_END:
            strhdl->ptr = data->str + data->len - offset;
            if (strhdl->ptr < data->str)
                strhdl->ptr = data->str;
            break;
    }
    return strhdl->ptr - data->str;
}



static int query_dentry(struct shim_dentry* dent, mode_t* mode,
                        struct stat* stat) {
    int ret = 0;

    struct shim_tmpfs_data* data;
    if ((ret = try_create_data(dent, &data)) < 0)
        return ret;

    lock(&data->lock);

    if (dent){
                    
        switch (data->type) {
            case FILE_REGULAR:
                dent->type = S_IFREG;
                break;
            case FILE_DIR:
                dent->type = S_IFDIR;
                break;
            default:
                unlock(&data->lock);
                return -ENOENT;
                break;
        }
    }

    if (mode)
        *mode = data->mode;

    if (stat) {
        memset(stat, 0, sizeof(struct stat));

        stat->st_mode  = (mode_t)data->mode;
        stat->st_dev   = 0;
        stat->st_ino   = 0;
        stat->st_size  = data->str_data.len;
        stat->st_atime = (time_t)data->atime;
        stat->st_mtime = (time_t)data->mtime;
        stat->st_ctime = (time_t)data->ctime;
        stat->st_nlink = data->nlink;

        switch (data->type) {
            case FILE_REGULAR:
                stat->st_mode |= S_IFREG;
                break;
            case FILE_DIR:
                stat->st_mode |= S_IFDIR;
                break;
            default:
                break;
        }
    }

    unlock(&data->lock);
    return 0;
}

static int tmpfs_mode(struct shim_dentry* dent, mode_t* mode) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_mode(/*name=*/NULL, mode);
    }
    return query_dentry(dent, mode, NULL);
}

static int tmpfs_stat(struct shim_dentry* dent, struct stat* statbuf) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_stat(/*name=*/NULL, statbuf);
    }
    return query_dentry(dent, NULL, statbuf);
}

static int tmpfs_lookup(struct shim_dentry* dent) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        dent->ino    = 1;
        dent->state |= DENTRY_ISDIRECTORY;
        return 0;
    }
    return query_dentry(dent, NULL, NULL);
}


static int __tmpfs_creat(struct shim_dentry* dent, int flags, mode_t mode,
                         struct shim_handle* hdl, struct shim_tmpfs_data* data) {

}


static int tmpfs_creat(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                        int flags, mode_t mode) {
    int ret = 0;
    struct shim_tmpfs_data* data;
    if ((ret = try_create_data(dent, &data)) < 0)
        return ret;

    if (!hdl)
        return 0;

    if (data->type == FILE_DIR) {
        return -EISDIR;
    }
    if ((ret = tmpfs_open(hdl, dent, flags | O_CREAT | O_EXCL)) < 0)
        return ret;

    data->mode =mode;
#if 0 //move to open
    struct shim_str_handle* str = &hdl->info.str;

    data->type = FILE_REGULAR;
    data->mode = mode;
    /* initialize hdl, does not need a lock because no one is sharing */
    hdl->type     = TYPE_STR;
    hdl->flags    = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
#endif
    /* Increment the parent's link count */
    struct shim_tmpfs_data* parent_data = (struct shim_tmpfs_data*)(dir)->data;
    if (parent_data) {
        lock(&parent_data->lock);
        if (parent_data->queried)
            parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return 0;
}

static int tmpfs_mkdir(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode) {
    int ret = 0;
    struct shim_tmpfs_data* data;
    if ((ret = try_create_data(dent, &data)) < 0)
        return ret;

    if (data->type != FILE_UNKNOWN)
        return -EEXIST;
    data->type = FILE_DIR;
    data->mode = 0777;
    //(R_OK | W_OK | X_OK) << 6 | (R_OK | W_OK | X_OK) << 3 | (R_OK | W_OK | X_OK);

    dent->type = S_IFDIR;
    //always keep handle for tmpfs until unlink
    //get_handle(hdl);

    /* Increment the parent's link count */
    struct shim_tmpfs_data* parent_data = (struct shim_tmpfs_data*)(dir)->data;
    if (parent_data) {
        lock(&parent_data->lock);
        if (parent_data->queried)
            parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return ret;
}

#define NEED_RECREATE(hdl) (!FILE_HANDLE_DATA(hdl))

static int tmpfs_recreate(struct shim_handle* hdl) {
    struct shim_tmpfs_data* data = FILE_HANDLE_DATA(hdl);
    int ret = 0;

    /* quickly bail out if the data is created */
    if (data)
        return 0;

    if (hdl->dentry) {
        if ((ret = try_create_data(hdl->dentry, &data)) < 0)
            return ret;
    } else {
        data = __create_data();
        if (!data)
            return -ENOMEM;
    }
}

static int tmpfs_hstat(struct shim_handle* hdl, struct stat* stat) {
    int ret;
    if (NEED_RECREATE(hdl) && (ret = tmpfs_recreate(hdl)) < 0)
        return ret;

    assert(hdl->dentry);
    if (qstrempty(&hdl->dentry->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_stat(/*name=*/NULL, stat);
    }
    return query_dentry(hdl->dentry, NULL, stat);
}


static int tmpfs_truncate(struct shim_handle* hdl, off_t len) {
    int ret = 0;

    if (NEED_RECREATE(hdl) && (ret = tmpfs_recreate(hdl)) < 0)
        return ret;

    if (!(hdl->acc_mode & MAY_WRITE))
        return -EINVAL;

    struct shim_str_data* data = hdl->info.str.data;
    lock(&hdl->lock);
    data->len      = len;
out:
    unlock(&hdl->lock);
    return ret;
}

static int tmpfs_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    struct shim_tmpfs_data* data = NULL;
    int ret = 0;
    PAL_HANDLE pal_hdl = NULL;
    size_t buf_size = MAX_PATH;
    size_t dirent_buf_size = 0;
    char* buf = NULL;
    char* dirent_buf = NULL;
    int nchildren = dent->nchildren;

    
    struct shim_tmpfs_data* tmpfs_data = dent->data;
    if (!tmpfs_data) {
        return -ENOENT;
    }
    if (tmpfs_data->type != FILE_DIR) {
        return -ENOTDIR;
    }
 
#if 0
    while (1) {
        /* DkStreamRead for directory will return as many entries as fits into the buffer. */
        PAL_NUM bytes = DkStreamRead(pal_hdl, 0, buf_size, buf, NULL, 0);
        if (bytes == PAL_STREAM_ERROR) {
            if (PAL_NATIVE_ERRNO() == PAL_ERROR_ENDOFSTREAM) {
                /* End of directory listing */
                ret = 0;
                break;
            }

            ret = -PAL_ERRNO();
            goto out;
        }
        /* Last entry must be null-terminated */
        assert(buf[bytes - 1] == '\0');

        size_t dirent_cur_off = dirent_buf_size;
        /* Calculate needed buffer size */
        size_t len = buf[0] != '\0' ? 1 : 0;
        for (size_t i = 1; i < bytes; i++) {
            if (buf[i] == '\0') {
                /* The PAL convention: if a name ends with '/', it is a directory.
                 * struct shim_dirent has a field for a type, hence trailing slash
                 * can be safely discarded. */
                if (buf[i - 1] == '/') {
                    len--;
                }
                dirent_buf_size += SHIM_DIRENT_ALIGNED_SIZE(len + 1);
                len = 0;
            } else {
                len++;
            }
        }

        /* TODO: If realloc gets enabled delete following and uncomment rest */
        char* tmp = malloc(dirent_buf_size);
        if (!tmp) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(tmp, dirent_buf, dirent_cur_off);
        free(dirent_buf);
        dirent_buf = tmp;
        /*
        dirent_buf = realloc(dirent_buf, dirent_buf_size);
        if (!dirent_buf) {
            ret = -ENOMEM;
            goto out;
        }
        */

        size_t i = 0;
        while (i < bytes) {
            char* name = buf + i;
            size_t len = strnlen(name, bytes - i);
            i += len + 1;
            bool is_dir = false;

            /* Skipping trailing slash - explained above */
            if (name[len - 1] == '/') {
                is_dir = true;
                name[--len] = '\0';
            }

            struct shim_dirent* dptr = (struct shim_dirent*)(dirent_buf + dirent_cur_off);
            dptr->ino  = rehash_name(dent->ino, name, len);
            dptr->type = is_dir ? LINUX_DT_DIR : LINUX_DT_REG;
            memcpy(dptr->name, name, len + 1);

            dirent_cur_off += SHIM_DIRENT_ALIGNED_SIZE(len + 1);
        }
    }

    *dirent = (struct shim_dirent*)dirent_buf;

    /*
     * Fix next field of struct shim_dirent to point to the next entry.
     * Since all entries are assumed to come from single allocation
     * (as free gets called just on the head of this list) this should have
     * been just entry size instead of a pointer (and probably needs to be
     * rewritten as such one day).
     */
    struct shim_dirent** last = NULL;
    for (size_t dirent_cur_off = 0; dirent_cur_off < dirent_buf_size;) {
        struct shim_dirent* dptr = (struct shim_dirent*)(dirent_buf + dirent_cur_off);
        size_t len = SHIM_DIRENT_ALIGNED_SIZE(strlen(dptr->name) + 1);
        dptr->next = (struct shim_dirent*)(dirent_buf + dirent_cur_off + len);
        last = &dptr->next;
        dirent_cur_off += len;
    }
    if (last) {
        *last = NULL;
    }

out:
    /* Need to free output buffer if error is returned */
    if (ret) {
        free(dirent_buf);
    }
    free(buf);
    DkObjectClose(pal_hdl);
#endif
    return ret;
}

static int tmpfs_checkout(struct shim_handle* hdl) {
    return 0;
}

static ssize_t tmpfs_checkpoint(void** checkpoint, void* mount_data) {
    return 0;
}

static int tmpfs_migrate(void* checkpoint, void** mount_data) {
    return 0;
}

static int tmpfs_unlink(struct shim_dentry* dir, struct shim_dentry* dent) {
    int ret;
    struct shim_tmpfs_data* tmpfs_data = dent->data;

    dent->mode = NO_MODE;
    if (tmpfs_data) {
        tmpfs_data->mode = 0;
        if (tmpfs_data->type == FILE_REGULAR)
        {
            struct shim_str_data* data = &tmpfs_data->str_data;

            REF_DEC(data->ref_count);
            if (data->str) {
                free(data->str);
                data->str = NULL;
            }

            data->len      = 0;
            data->buf_size = 0;
        }
        else if (tmpfs_data->type == FILE_DIR && 
            dent->nchildren != 0)
        {
            return -ENOTEMPTY;
        }
        

        free(dent->data);
        dent->data = NULL;
    }

    /*TODO remove dentry from parent dir dentry
void remove_dentry(struct shim_dentry* dir, struct shim_dentry* dent) {
    if (parent) {
        // Increment both dentries' ref counts once they are linked
        put_dentry(parent);
        put_dentry(dent);
        LISTP_REMOVE(dent, &parent->children, siblings);
        dent->parent = NULL;
        parent->nchildren--;

    }
}
*/

    /* Drop the parent's link count */
    struct shim_tmpfs_data* parent_data = dir->data;
    if (parent_data) {
        lock(&parent_data->lock);
        parent_data->nlink--;
        unlock(&parent_data->lock);
    }

    //always keep handle for tmpfs until unlink
    //put_handle(hdl);

    return 0;
}

static off_t tmpfs_poll(struct shim_handle* hdl, int poll_type) {
    int ret;
    struct shim_str_data* data = hdl->info.str.data;
    off_t size = data->len;

    if (poll_type == FS_POLL_SZ)
        return size;

    return (poll_type & FS_POLL_WR) | (poll_type & FS_POLL_RD);
}

static int tmpfs_rename(struct shim_dentry* old, struct shim_dentry* new) {
    int ret;
    

    struct shim_tmpfs_data* tmpfs_data = new->data;
    assert(tmpfs_data  && tmpfs_data->str_data.str == NULL);

    new->data = old->data;
    __destroy_data(tmpfs_data);
    old->data = NULL;

    new->mode = old->mode;
    old->mode = NO_MODE;

    new->type = old->type;

    uint64_t time = DkSystemTimeQuery();
    if (time == (uint64_t)-1)
        time = 0;
    
    tmpfs_data = new->data;
    tmpfs_data->atime = time / 1000000;
    tmpfs_data->mtime = tmpfs_data->atime;
    tmpfs_data->ctime = tmpfs_data->atime;


    return 0;
}

static int tmpfs_chmod(struct shim_dentry* dent, mode_t mode) {
    int ret;
    struct shim_tmpfs_data* tmpfs_data = dent->data;
    dent->mode = mode;
    tmpfs_data->mode = mode;

    uint64_t time = DkSystemTimeQuery();
    if (time == (uint64_t)-1)
        time = 0;
    tmpfs_data->ctime = time / 1000000;
    return 0;
}
struct shim_fs_ops tmp_fs_ops = {
    .mount      = &tmpfs_mount,
    .unmount    = &tmpfs_unmount,
    .flush      = &tmpfs_flush,
    .close      = &tmpfs_close,
    .read       = &tmpfs_read,
    .write      = &tmpfs_write,
    .mmap       = tmpfs_mmap,
    .seek       = &tmpfs_seek,
    .hstat      = &tmpfs_hstat,
    .truncate   = &tmpfs_truncate,
    .checkout   = &tmpfs_checkout,
    .checkpoint = &tmpfs_checkpoint,
    .migrate    = &tmpfs_migrate,
    .poll       = &tmpfs_poll,
};

struct shim_d_ops tmp_d_ops = {
    .open    = &tmpfs_open,
    .mode    = &tmpfs_mode,
    .lookup  = &tmpfs_lookup,
    .creat   = &tmpfs_creat,
    .mkdir   = &tmpfs_mkdir,
    .stat    = &tmpfs_stat,
    .dput    = &tmpfs_dput,
    .readdir = &tmpfs_readdir,
    .unlink  = &tmpfs_unlink,
    .rename  = &tmpfs_rename,
    .chmod   = &tmpfs_chmod,
};
