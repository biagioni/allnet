/* packet.h: definition of AllNet packet headers */

#ifndef MEDIA_H
#define MEDIA_H

/* common media types */
#define ALLNET_MEDIA_TEXT_PLAIN		1	   /* UTF-8 text */
#define ALLNET_MEDIA_TEXT_HTML		2	   /* UTF-8 text */
#define ALLNET_MEDIA_TEXT_XML		3	   /* UTF-8 text */
#define ALLNET_MEDIA_TEXT_VCARD		4	   /* UTF-8 text */

#define ALLNET_MEDIA_DATA		0x10000001 /* uninterpreted data */
#define ALLNET_MEDIA_COMPOUND	        0x10000002 /* compound, see below */
#define ALLNET_MEDIA_HTMLPLUS	        0x10000003 /* html w/media, see below */

#define ALLNET_MEDIA_AUDIO_RAW		0x20000001 /* WAV raw LPCM audio */
#define ALLNET_MEDIA_AUDIO_BASIC	0x20000002 /* mu-law 8KHz audio */
#define ALLNET_MEDIA_AUDIO_MP4		0x20000003 /* MP4 audio */
#define ALLNET_MEDIA_AUDIO_OGG_VORBIS	0x20000004 /* Ogg Vorbis audio */

#define ALLNET_MEDIA_IMAGE_RAW_TIFF	0x30000001 /* TIFF/EP raw image */
#define ALLNET_MEDIA_IMAGE_RAW_EXIF	0x30000002 /* Exif/TIFF raw image */
#define ALLNET_MEDIA_IMAGE_JPEG		0x30000003 /* JPEG compressed image */
#define ALLNET_MEDIA_IMAGE_PNG		0x30000004 /* PNG compressed image */
#define ALLNET_MEDIA_IMAGE_GIF		0x30000005 /* GIF compressed image */
#define ALLNET_MEDIA_IMAGE_SVG		0x30000006 /* SVG vector image */

#define ALLNET_MEDIA_VIDEO_WEBM		0x40000002 /* WebM compressed video */
#define ALLNET_MEDIA_VIDEO_MPEG		0x40000003 /* MPEG-1 video/audio */
#define ALLNET_MEDIA_VIDEO_MP4		0x40000004 /* MP4 video/audio */
#define ALLNET_MEDIA_VIDEO_OGG_THEORA	0x40000005 /* Ogg Theora video */
#define ALLNET_MEDIA_VIDEO_QUICKTIME	0x40000006 /* Quicktime video */
#define ALLNET_MEDIA_VIDEO_AVI		0x40000007 /* AVI video */

/* allnet-specific media types */
#define ALLNET_MEDIA_EARTH_POSITION	0x80000001 /* see below */
#define ALLNET_MEDIA_TIME_TEXT_BIN	0x80000002 /* in UTF-8 then binary */
#define ALLNET_MEDIA_PUBLIC_KEY		0x80000003
#define ALLNET_MEDIA_PROFILE	        0x80000004 /* same as compound */

/* for development purposes */
#define ALLNET_MEDIA_TESTING_1		0xE0000001
#define ALLNET_MEDIA_TESTING_2		0xE0000002
#define ALLNET_MEDIA_TESTING_3		0xE0000003
#define ALLNET_MEDIA_TESTING_4		0xE0000004
#define ALLNET_MEDIA_TESTING_5		0xE0000005
#define ALLNET_MEDIA_TESTING_6		0xE0000006
#define ALLNET_MEDIA_TESTING_7		0xE0000007
#define ALLNET_MEDIA_TESTING_8		0xE0000008
/* might be useful*/
#define ALLNET_MEDIA_UNKNOWN		0xFFFFFFFF

/* a compound data in AllNet format is a sequence of entries, each of format: */
struct allnet_compound_data {
  /* the media field may be ALLNET_MEDIA_COMPOUND_ALLNET, allowing recursion */
  unsigned char media [ALLNET_MEDIA_ID_SIZE];
  /* if 1, the field is terminated by the string.  If 0, the field has
   * length given by the string (interpreted in binary big-endian) */
  unsigned char terminated_not_length;
  unsigned char term_or_length_size;   /* number of bytes in term_or_length */
  /* if terminated_not_length > 0, term_or_length contains the terminating
   * string that indicates the end of the content.
   * if terminated_not_length == 0, term_or_length contains the length
   * of the content, in bytes. */
  unsigned char term_or_length [0 /* really, term_or_length_size */ ]; 
};

/* an html-plus is the same as a compound, but the first entry is what
 * is displayed, and the others may aid in the display.  Each entry i in 1..n
 * may be referred to with the URI amh://i */

/* a profile is the same as a compound.  It will typically have a vcard
 * and one or more images */

/* a geographic location in AllNet is given by three coordinates: 
 * a latitude, a longitude, and a height
 * each is given in units of from the equator at the prime meridian
 * and the year 2000 mean sea level (Y2K msl) position.
 * one unit of lat/lon is 360 degrees / 2^32  (approx 0.093m)
 * one unit of height is 1 cm
 * latitude is positive to the east, negative to the west
 * longitude is positive to the north, negative to the south, and the distance
 *   is measured along the equator (~11111111 cm/deg)
 * height is positive upwards, negative downwards 
 * each number is encoded as a big-endian signed 2's complement binary
 * each number also has an accuracy, a number of valid bits, in 0..32
 * (counting from the most significant bit).  If the accuracy is zero,
 * the coordinate is unspecified.
 * height is taken from msl at the given position, or at the equator if
 * latitude is unspecified, or at the prime meridian for unspecified longitude
 * examples: Mt. Everest is at 27.988N, 86.925W, and 8,848m above msl,
 *   units/degree (upd) = 2^32 / 360 = 11930464.7111111111
 *   latitude  27.988 * upd ~=  333910000 = 0x13E70FF0
 *   longitude 86.925 * upd ~= 1037100000 = 0x3DD0E3E0
 *   height    8,848 * 100 =       884800 = 0x000D8040
 * Mt. Aconcagua, at 32.653S, 70.011W, 6960m, would be
 *   lat 0xE8C7B3E8, lon 0xCE36E2EB, height 0x000A9EC0
 */
struct allnet_earth_position {
  unsigned char latitude [4];
  unsigned char longitude [4];
  unsigned char height [4];
  unsigned char precision [4]; /* lat, lon, height, the last byte unused */
#define ALLNET_LAT_PRECISION_INDEX	0
#define ALLNET_LON_PRECISION_INDEX	1
#define ALLNET_HEIGHT_PRECISION_INDEX	2
};

#endif /* MEDIA_H */

