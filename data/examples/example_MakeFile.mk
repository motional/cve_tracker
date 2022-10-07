################################################################################
#
# ffmpeg
#
################################################################################

FFMPEG_VERSION = 4.4.0
FFMPEG_SOURCE = ffmpeg-$(FFMPEG_VERSION).tar.xz
FFMPEG_SITE = http://ffmpeg.org/releases
FFMPEG_INSTALL_STAGING = YES
FFMPEG_LICENSE = LGPL-2.1+, libjpeg license
FFMPEG_LICENSE_FILES = LICENSE.md COPYING.LGPLv2.1
ifeq ($(BR2_PACKAGE_FFMPEG_GPL),y)
FFMPEG_LICENSE += and GPL-2.0+
FFMPEG_LICENSE_FILES += COPYING.GPLv2
endif

FFMPEG_CPE_ID_VENDOR = ffmpeg


$(eval $(tools-package))
