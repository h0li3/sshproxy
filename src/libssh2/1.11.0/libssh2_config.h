/* Copyright (c) 2014 Alexander Lamaison <alexander.lamaison@gmail.com>
 * Copyright (c) 1999-2011 Douglas Gilbert. All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/* Headers */
/* #undef HAVE_UNISTD_H */
#define HAVE_INTTYPES_H
/* #undef HAVE_SYS_SELECT_H */
/* #undef HAVE_SYS_UIO_H */
/* #undef HAVE_SYS_SOCKET_H */
/* #undef HAVE_SYS_IOCTL_H */
/* #undef HAVE_SYS_TIME_H */
/* #undef HAVE_SYS_UN_H */

/* for example and tests */
/* #undef HAVE_SYS_PARAM_H */
/* #undef HAVE_ARPA_INET_H */
/* #undef HAVE_NETINET_IN_H */

/* Functions */
/* #undef HAVE_GETTIMEOFDAY */
#define HAVE_STRTOLL
/* #undef HAVE_STRTOI64 */
#define HAVE_SNPRINTF
/* #undef HAVE_EXPLICIT_BZERO */
/* #undef HAVE_EXPLICIT_MEMSET */
/* #undef HAVE_MEMSET_S */

/* #undef HAVE_POLL */
#define HAVE_SELECT

/* Socket non-blocking support */
/* #undef HAVE_O_NONBLOCK */
/* #undef HAVE_FIONBIO */
/* #undef HAVE_IOCTLSOCKET_CASE */
/* #undef HAVE_SO_NONBLOCK */

/* attribute to export symbol */
#if defined(LIBSSH2_EXPORTS) && defined(LIBSSH2_LIBRARY)
/* #undef LIBSSH2_API */
#endif
