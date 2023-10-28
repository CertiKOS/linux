/**
 * @file cmd_ring.h
 * @brief command ring buffer
 * a single producer, single consumer ring buffer
 * with two lists:
 * command list: [head - middle]
 * result list: [middle - tail]
 *
 * @version 0.1
 * @date 2019-05-21
 */
#ifndef _LIB_CMD_RING_
#define _LIB_CMD_RING_

#ifndef gcc_inline
#define gcc_inline			static inline /*__attribute__((always_inline))*/
#endif

#ifndef gcc_packed
#define gcc_packed          __attribute__((packed))
#endif

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;

typedef uint8_t 			cr_status_t;

/* bit [0]: result / command */
#define PACKET_RST			((cr_status_t)  0u)
#define PACKET_CMD			((cr_status_t)  1u)

/* bit [1]: fresh / stale */
#define PACKET_STALE		((cr_status_t)  0u)
#define PACKET_FRESH		((cr_status_t)  2u)

/* bit [3]: valid / failed */
#define PACKET_VALID		((cr_status_t)  0u)
#define PACKET_FAILED		((cr_status_t)  4u)

/* combination */
#define EMPTY				(PACKET_VALID | PACKET_STALE | PACKET_RST)
#define ISSUED				(PACKET_VALID | PACKET_FRESH | PACKET_CMD)
#define PROCESSING			(PACKET_VALID | PACKET_STALE | PACKET_CMD)
#define RETURN				(PACKET_VALID | PACKET_FRESH | PACKET_RST)
#define FAILED				(PACKET_FAILED)

/**
 *   init
 * +-------+
 *         |
 *   +-----v----+  commit  +----------+
 *   |  EMPTY   +--------->+  ISSUED  |
 *   +-------+--+          +--+-------+
 *           ^    +------+    |
 *pop_result |    |FAILED|    | next_command
 *           |    +------+    v
 *   +-------+--+          +--+-------+
 *   | RETURNED +<---------+PROCESSING|
 *   +----------+          +----------+
 *               set_result
 *
 */

__attribute__((weak)) const char* packet_status_str[] =
{
	[EMPTY]      = "empty",
	[ISSUED]     = "issued",
	[PROCESSING] = "processing",
	[RETURN]     = "returned",
	[FAILED]     = "failed",
};

#define CR_DATA_SIZE		(4u)
#define CR_BUFFER_SIZE		(64u)
#define CR_INV_NODE			CR_BUFFER_SIZE

struct packet_t
{
	cr_status_t		status;
	uint8_t			type;
	uint16_t		id;
	uint32_t		data[4];
} gcc_packed;


/**
 *         mid
 * tail-+   +   +-->head
 *      v   v   v
 *   +-+-+--+--+-+-+---+-+
 *   | | |r|r|i|i| |...| |
 *   +-+-+-+-+-+-+-+---+-+
 *    0 1 2 3 4 5 6 ... CR_BUFFER_SIZE
 * note{ : empty, r: returned, i: issued }
 */
struct command_ring_t
{
	struct packet_t	packets[CR_BUFFER_SIZE];
	uint16_t		next_id;	/**< next packet id */
	uint16_t		error;		/**< if results contain any error */
	size_t			head;		/**< command head */
	size_t			mid;		/**< command tail, also result head */
	size_t			tail;		/**< result tail */
};

gcc_inline void
cr_init(struct command_ring_t * cr)
{
	size_t i;
	for (i = 0; i < CR_BUFFER_SIZE; i++)
	{
		cr->packets[i].status = EMPTY;
	}
	cr->next_id = 0;
	cr->head    = 0;
	cr->mid     = 0;
	cr->tail    = 0;
}

gcc_inline size_t
cr_alloc_command(struct command_ring_t * cr)
{
	size_t i = (cr->head + 1) % CR_BUFFER_SIZE;

	if (i == cr->tail)
	{
		return (CR_INV_NODE);
	}

	cr->packets[i].id     = cr->next_id;
	cr->next_id ++;

	return (i);
}

gcc_inline void
cr_commit_command(struct command_ring_t* cr, size_t idx)
{
	if (idx == CR_INV_NODE)
	{
		/* reject to commit a command in a invalid position */
		return ;
	}

	cr->head = idx;
	cr->packets[idx].status = ISSUED;
}

gcc_inline size_t
cr_next_command(struct command_ring_t* cr)
{
	if (cr->mid == cr->head)
	{
		return (CR_INV_NODE);
	}

	size_t i = (cr->mid + 1) % CR_BUFFER_SIZE;
	cr->packets[i].status = PROCESSING;
	return (i);
}

gcc_inline void
cr_set_result(struct command_ring_t* cr, size_t idx)
{
	if (idx == CR_INV_NODE)
	{
		/* reject to set result of a invalid command */
		return;
	}

	cr->mid = idx;
	cr->packets[idx].status = RETURN;
}

gcc_inline void
cr_pop_result(struct command_ring_t* cr)
{
	if (cr->tail == cr->mid)
	{
		/* nothing to clear */
		return;
	}

	cr->packets[cr->tail].status = EMPTY;
	cr->tail = (cr->tail + 1) % CR_BUFFER_SIZE;
}

gcc_inline void
cr_empty_result(struct command_ring_t* cr)
{
	cr->tail = cr->mid;
}

#endif /* !_LIB_CMD_RING_ */
