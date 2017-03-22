#include <sys/types.h>
#include <sys/w32_types.h>

struct uio *uio_create(
	int a_iovcount,             /* max number of iovecs */
	off_t a_offset,             /* current offset */
	int a_spacetype,            /* type of address space */
	int a_iodirection )         /* read or write flag */
{
	return NULL;
}

user_addr_t uio_curriovbase( struct uio *a_uio )
{
	return 0;
}

int uio_iovcnt( struct uio *a_uio )
{
	return 0;
}

void uio_free( struct uio *a_uio )
{
}

int uio_addiov(struct uio *o,user_addr_t a_baseaddr,user_size_t a_length )
{
	return -1;
}

int uio_getiov( struct uio *a_uio,
                 int a_index,
                 user_addr_t * a_baseaddr_p,
                 user_size_t * a_length_p )
{
	return -1;
}

user_size_t uio_curriovlen( struct uio *a_uio )
{
	return 0;
}

int uio_isuserspace( struct uio *a_uio )
{
	return 0;
}

user_size_t uio_resid( struct uio *a_uio )
{
	return 0;
}

void uio_setrw( struct uio *a_uio, int a_value )
{
}

int uiomove(const char * cp, int n, int r, struct uio *uio)
{
	return 0;
}

void uio_update( struct uio *a_uio, user_size_t a_count )
{

}

off_t uio_offset( struct uio *a_uio )
{
	return 0;
}

void uio_reset( struct uio *a_uio, off_t a_offset, int a_spacetype,
				int a_iodirection )
{

}
