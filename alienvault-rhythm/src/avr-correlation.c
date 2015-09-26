/*
  License:

  Copyright (c) 2015 AlienVault
  All rights reserved.

  This package is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 dated June, 1991.
  You may not use, modify or distribute this program under any other version
  of the GNU General Public License.

  This package is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this package; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA  02110-1301  USA


  On Debian GNU/Linux systems, the complete text of the GNU General
  Public License can be found in `/usr/share/common-licenses/GPL-2'.

  Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include "avr-correlation.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <glib/gstdio.h>

#include "avr-db.h"
#include "radix-tree.h"

struct _AvrCorrelationPrivate
{
  AvrType        type;
  AvrDb *        db;
  gchar *        file_path;
  GIOChannel *   file_channel;
  AvrLog *       event_log;
  AvrTld *       domains;

  gint           lines_parsed;
  gint           lines_matched;
  goffset        start_position;
  guint64        events_processed;

};

static gpointer parent_class = NULL;

//
// Static declarations.
//
static gpointer         _avr_correlation_loop              (gpointer);
static GPtrArray *      _avr_correlation_parse_line        (AvrCorrelation *, const gchar *, gsize);
static gchar *          _avr_correlation_match_ip_address  (AvrCorrelation *, GPtrArray *);
static gchar *          _avr_correlation_match_string      (AvrCorrelation *, GPtrArray *);
static GString *        _avr_correlation_build_list_string (GHashTable     *, GPtrArray *);

// GType Functions

static void
avr_correlation_impl_dispose (GObject * gobject)
{
  G_OBJECT_CLASS (parent_class)->dispose (gobject);
}

static void
avr_correlation_impl_finalize (GObject * gobject)
{
  AvrCorrelation * correlation = AVR_CORRELATION (gobject);

  if (correlation->_priv->db)
    g_object_unref(correlation->_priv->db);

  if (correlation->_priv->domains)
    g_object_unref (correlation->_priv->domains);

  if (correlation->_priv->file_path)
    g_free(correlation->_priv->file_path);

  if (correlation->_priv->file_channel)
    g_io_channel_unref(correlation->_priv->file_channel);

  if (correlation->_priv->event_log)
  {
    g_object_unref(correlation->_priv->event_log);
  }

  g_free (correlation->_priv);

  G_OBJECT_CLASS (parent_class)->finalize (gobject);
}

static void
avr_correlation_class_init (AvrCorrelationClass * class)
{
  GObjectClass * object_class = G_OBJECT_CLASS (class);

  parent_class = g_type_class_peek_parent (class);

  object_class->dispose = avr_correlation_impl_dispose;
  object_class->finalize = avr_correlation_impl_finalize;
}

static void
avr_correlation_instance_init (AvrCorrelation * correlation)
{
  correlation->_priv = g_new0 (AvrCorrelationPrivate, 1);

  return;
}

GType
avr_correlation_get_type (void)
{
  static GType object_type = 0;

  if (!object_type)
  {
    static const GTypeInfo type_info = {
      sizeof (AvrCorrelationClass),
      NULL,
      NULL,
      (GClassInitFunc) avr_correlation_class_init,
      NULL,
      NULL,                       /* class data */
      sizeof (AvrCorrelation),
      0,                          /* number of pre-allocs */
      (GInstanceInitFunc) avr_correlation_instance_init,
      NULL                        /* value table */
    };

    g_type_init ();
    object_type = g_type_register_static (G_TYPE_OBJECT, "AvrCorrelation", &type_info, 0);
  }
  return object_type;
}

/**
 * avr_correlation_init:
 *
 *
 */
void
avr_correlation_init (void)
{

}

/**
 * avr_correlation_clear:
 *
 *
 */
void
avr_correlation_clear (void)
{

}

/**
 * avr_correlation_new:
 * @void
 *
 *
 * Returns:
 */
AvrCorrelation *
avr_correlation_new (AvrType type,
                     AvrLog * event_log,
                     const gchar * db_socket_path,
                     AvrTld *tld)
{
  g_return_val_if_fail (type < AVR_TYPES, NULL);
  g_return_val_if_fail (AVR_IS_LOG(event_log), NULL);

  AvrCorrelation * correlation = NULL;
  const gchar * file_path = "/var/log/suricata/eve.json";  // TODO: make this parametric.
  gint file_fd = 0;
  GError * error = NULL;

  // Thread subsystem init
  if (!g_thread_supported ())
    g_thread_init (NULL);

  correlation = AVR_CORRELATION(g_object_new (AVR_TYPE_CORRELATION, NULL));
  correlation->_priv->type = type;

  correlation->_priv->db = avr_db_new_unix(correlation->_priv->type, db_socket_path);
  if (correlation->_priv->db == NULL)
  {
    g_object_unref(correlation);
    return (NULL);
  }

  if (!(g_file_test(file_path, G_FILE_TEST_IS_REGULAR)))
  {
    g_message ("File \"%s\" not found, so it will be created", file_path);
    if ((file_fd = open (file_path, O_CREAT)) < 0)
    {
      g_critical ("Cannot create file \"%s\"", file_path);
      g_object_unref (correlation);
      return (NULL);
    }
    close(file_fd);

    if (chmod(file_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH) != 0)
    {
      g_critical ("Cannot change permissions for file \"%s\"", file_path);
      g_object_unref (correlation);
      return (NULL);
    }

    // Change owner & group.
    if (chown(file_path, 0, 0) != 0)
    {
      g_critical ("Cannot change \"%s\" owner and group", file_path);
      g_object_unref (correlation);
      return (NULL);
    }
  }

  correlation->_priv->file_path = g_strdup_printf("%s", file_path);

  correlation->_priv->file_channel = g_io_channel_new_file((const gchar *)correlation->_priv->file_path, "r", &error);
  if (error != NULL)
  {
    g_critical ("File \"%s\" cannot be opened: %s", correlation->_priv->file_path, error->message);
    g_object_unref(correlation);
    g_error_free(error);
    return (NULL);
  }

  // TODO: inc this with the object reference.
  correlation->_priv->event_log = g_object_ref (event_log);

  correlation->_priv->lines_parsed = 0;
  correlation->_priv->lines_matched = 0;
  correlation->_priv->events_processed = 0;

  if (tld != NULL)
  {
    correlation->_priv->domains = g_object_ref (tld);
  }

  return (correlation);
}

/**
 * avr_correlation_run:
 * @void
 *
 *
 * Returns:
 */
goffset
avr_correlation_run (AvrCorrelation * correlation,
                     goffset          current_position)
{
  g_return_val_if_fail (AVR_IS_CORRELATION(correlation), G_MINOFFSET);

  GThread * loop_thread = NULL;
  GError * error = NULL;
  FILE *fd;

  if (current_position == G_MINOFFSET)
  {
    if (g_file_test (correlation->_priv->file_path, G_FILE_TEST_EXISTS) == FALSE)
    {
      current_position = 0;
    }
    else
    {
      fd = g_fopen (correlation->_priv->file_path, "r");
      if (fd == NULL)
      {
        g_critical ("Cannot open file %s", correlation->_priv->file_path);
        return G_MINOFFSET;
      }

      fseek (fd, 0, SEEK_END);
      current_position = ftell(fd);
    }
  }

  correlation->_priv->start_position = current_position;

  loop_thread = g_thread_create((GThreadFunc)_avr_correlation_loop, (gpointer)correlation, FALSE, &error);
  if ((loop_thread == NULL) || (error != NULL))
  {
    if (error != NULL)
    {
      g_critical ("Cannot create main correlation thread: %s", error->message);
      g_error_free(error);
    }
    else
    {
      g_critical ("Cannot create main correlation thread: %s", error->message);
    }
  }

  return current_position;
}


//
// Private methods
//

/**
 * _avr_correlation_loop:
 * @void
 *
 *
 * Returns:
 */
static gpointer
_avr_correlation_loop (gpointer avr_correlation_ptr)
{
  AvrCorrelation * correlation = AVR_CORRELATION (avr_correlation_ptr);
  time_t last_time = 0;
  time_t current_time = 0;
  const gchar * avr_type_names[] = {"IP Address", "File Hash", "Domain", "Hostname", NULL};
  GIOStatus file_status = G_IO_STATUS_NORMAL;
  struct stat file_stat;
  gchar * header_str = NULL, * line_str = NULL;
  gsize line_len = 0, line_term = 0, file_len = 0;
  gsize utf8_line_len = 0;
  GPtrArray * parsed_array = NULL;
  gchar * result_str = NULL;
  GError * error = NULL;

  // Set cursor at the end.
  g_debug ("Starting thread at position %lld", (long long int)correlation->_priv->start_position);

  if ((file_status = g_io_channel_seek_position (correlation->_priv->file_channel, (gint64) correlation->_priv->start_position, G_SEEK_SET, &error)) != G_IO_STATUS_NORMAL)
  {
    if (error != NULL)
    {
      g_warning ("Cannot set pointer at the end of \"%s\": %s", correlation->_priv->file_path, error->message);
      g_error_free(error);
    }
    else
    {
      g_warning ("Cannot set pointer at the end of \"%s\"", correlation->_priv->file_path);
    }
    return (NULL);
  }

  while (TRUE)
  {
    // Show some fancy stats.
    current_time = time(NULL);
    if ((current_time != last_time) && ((current_time % 10) == 0))
    {
      g_message ("Type: %s; Events processed: %ld; IoC matched: %d",
                 avr_type_names[correlation->_priv->type],
                 correlation->_priv->events_processed,
                 g_atomic_int_get (&correlation->_priv->lines_matched));

      last_time = current_time;
    }

    // Read the file, line by line.
    file_status = g_io_channel_read_line (correlation->_priv->file_channel, &line_str, &line_len, &line_term, &error);

    if (!(file_status & (G_IO_STATUS_NORMAL | G_IO_STATUS_EOF)) || (error != NULL))
    {
      if (error != NULL)
      {
        g_warning ("Cannot read file \"%s\": %s", correlation->_priv->file_path, error->message);
        g_error_free(error);
      }
      else
      {
        g_warning ("Cannot read file \"%s\"", correlation->_priv->file_path);
      }

      return (NULL);
    }

    if ((file_status == G_IO_STATUS_EOF))
    {
      if (line_str != NULL)
      {
        g_free (line_str);
        line_str = NULL;
      }

      // Has this file been truncated? Let us see...
      if (stat(correlation->_priv->file_path, &file_stat) == 0)
      {
        if (file_stat.st_size < (off_t)file_len)
        {
          // Flush pending buffers.
          avr_log_flush_buffer (correlation->_priv->event_log);

          // Set cursor at the start of the new file.
          if ((file_status = g_io_channel_seek_position (correlation->_priv->file_channel, 0, G_SEEK_SET, &error)) != G_IO_STATUS_NORMAL)
          {
            if (error != NULL)
            {
              g_warning ("Cannot set pointer at the start of \"%s\": %s", correlation->_priv->file_path, error->message);
              g_error_free(error);
            }
            else
            {
              g_warning ("Cannot set pointer at the start of \"%s\"", correlation->_priv->file_path);
            }
            return (NULL);
          }

          file_len = 0;
          correlation->_priv->lines_parsed = 0;
          g_message ("Thread: %s File has been truncated.",
                     avr_type_names[correlation->_priv->type]);
        }
      }
      else
      {
        g_warning ("Cannot stat file \"%s\"", correlation->_priv->file_path);
      }

      // Do not stop reading at the end of the file, as it should keep growing.
      // Give it some time, though.
      g_usleep(100000);
      continue;
    }

    file_len += (line_term + 1);

    // Ignore line if there is no otx data loaded
    if (avr_db_has_otx_data() == FALSE)
    {
      if (line_str != NULL)
      {
        g_free (line_str);
        line_str = NULL;
      }
      g_usleep(100);
      continue;
    }

    // Discard the line if it is not a valid event
    if (line_len < 10)
    {
      if (line_str != NULL)
      {
        g_free (line_str);
        line_str = NULL;
      }
      continue;
    }


    correlation->_priv->events_processed += 1;
    utf8_line_len = g_utf8_strlen(line_str, -1);

    // Parse a line, match a line.
    parsed_array = _avr_correlation_parse_line (correlation, line_str, utf8_line_len);

    // No need to trigger an awful error message here, just return.
    if (parsed_array != NULL)
    {
      if (parsed_array->len > 0)
      {
        switch(correlation->_priv->type)
        {
        case IP_ADDRESS:
          result_str = _avr_correlation_match_ip_address (correlation, parsed_array);
          break;

        case FILE_HASH:
        case DOMAIN:
        case HOSTNAME:
          result_str = _avr_correlation_match_string (correlation, parsed_array);
          break;

        default:
          g_warning("Invalid data type with id \"%d\" in correlation", correlation->_priv->type);
        }

        // Get the event header info.
        header_str = (gchar *)g_ptr_array_index (parsed_array, 0);

        // Send buffer to be written.
        avr_log_write_buffer (correlation->_priv->event_log, header_str, result_str, g_atomic_int_get (&correlation->_priv->lines_parsed));

        if (result_str != NULL)
        {
          g_atomic_int_inc (&correlation->_priv->lines_matched);
          g_free (result_str);
        }
      }

      g_ptr_array_unref (parsed_array);
      parsed_array = NULL;
    }

    // Free all pending resources.
    g_free (line_str);

    line_str = NULL;
    line_len = 0;
  }

  return (NULL);
}


/**
 * _avr_correlation_parse_line:
 * @void
 *
 *
 * Returns:
 */
static GPtrArray *
_avr_correlation_parse_line (AvrCorrelation * correlation, const gchar * line_str, gsize line_len)
{
  // A failure parsing a line is still considered as a parsed line.
  // Two or more threads will be concurrently reading the same file,
  // so to avoid mixing lines that cannot be parsed by one thread
  // with the same line parsed successfully in another, just take this
  // for granted.
  g_atomic_int_inc (&correlation->_priv->lines_parsed);

  g_return_val_if_fail (AVR_IS_CORRELATION(correlation), NULL);
  g_return_val_if_fail (line_str, NULL);
  g_return_val_if_fail (line_len > 10, NULL);

  GError * error = NULL;
  GPtrArray * parsed_array = NULL;
  JsonParser * parser = NULL;
  JsonReader * reader = NULL;
  const gchar * header_fields [] = {"timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", NULL};
  gint i = 0;
  GString * header_str = NULL;
  gchar * value = NULL;

  parser = json_parser_new ();
  if (json_parser_load_from_data (parser, line_str, line_len, &error) != TRUE)
  {
    g_object_unref (parser);
    parser = NULL;

    if (error != NULL)
      {
        // This could happen in, at least, two different situations
        //  1 - when the file is opened to be read, and it's being written very fast by an external process,
        //      when you set the cursor to the end of the file, you could be setting the cursor in the middle of the line
        //
        //  2 - When suricata stop writing logs and the latest line is not fully written, this causes the latest line to be an invalid json line
        g_debug("Cannot parse line from file \"%s\": %s Line:%s", correlation->_priv->file_path, error->message, line_str);
        g_error_free(error);
      }
      else
      {
        g_warning("Cannot parse line from file \"%s\"", correlation->_priv->file_path);
      }
    return (NULL);
  }

  reader = json_reader_new (json_parser_get_root (parser));
  g_object_unref (parser);
  parser = NULL;

  parsed_array = g_ptr_array_new_with_free_func ((GDestroyNotify)g_free);

  // Reader event header info first.
  header_str = g_string_new ("{");
  for (i = 0; header_fields[i] != NULL; i++)
  {
    if (json_reader_read_member (reader, header_fields[i]))
    {
      JsonNode * node = json_reader_get_value (reader);
      switch (json_node_get_value_type (node))
      {
       case G_TYPE_STRING:
           g_string_append_printf (header_str, "\"%s\": \"%s\",", header_fields[i], json_reader_get_string_value (reader));
           break;
         case G_TYPE_INT64:
           g_string_append_printf (header_str, "\"%s\": %ld,", header_fields[i], json_reader_get_int_value (reader));
           break;
         case G_TYPE_DOUBLE:
           g_string_append_printf (header_str, "\"%s\": %f,", header_fields[i], json_reader_get_double_value (reader));
           break;
         case G_TYPE_BOOLEAN:
           g_string_append_printf (header_str, "\"%s\": %s,", header_fields[i], json_reader_get_boolean_value (reader) ? "true":"false");
           break;
         default:
          g_warning("'%d' Unexpected value type", (gint) json_node_get_value_type (node));
       }
    }
    json_reader_end_member (reader);
  }

  // Append the whole log.
  g_string_append_printf (header_str, "\"log\": ");
  g_string_append_len (header_str, line_str, line_len - 1);
  g_string_append (header_str, ",");

  g_ptr_array_add (parsed_array, (gpointer)g_string_free (header_str, FALSE));

  switch(correlation->_priv->type)
  {
  case IP_ADDRESS:
    // Read "src_ip" and "dst_ip"
    if (json_reader_read_member (reader, "src_ip"))
    {
      value = g_strdup_printf ("%s", json_reader_get_string_value (reader));
      g_ptr_array_add (parsed_array, (gpointer)value);
    }
    json_reader_end_member (reader);

    if (json_reader_read_member (reader, "dest_ip"))
    {
      value = g_strdup_printf ("%s", json_reader_get_string_value (reader));
      g_ptr_array_add (parsed_array, (gpointer)value);
    }
    json_reader_end_member (reader);

    break;
  case FILE_HASH:
    // Read "md5" under "fileinfo"
    if (json_reader_read_member (reader, "fileinfo"))
    {
      if (json_reader_read_member (reader, "md5"))
      {
        value = g_utf8_strdown(json_reader_get_string_value (reader), -1);
        g_ptr_array_add (parsed_array, (gpointer)value);
      }
      json_reader_end_member (reader);
    }
    json_reader_end_member (reader);

    break;
  case DOMAIN:
    // Read "rrname" under "dns", if and only if it the type "answer" is present.
    if (json_reader_read_member (reader, "dns"))
    {
      if (json_reader_read_member (reader, "type"))
      {
        if (!g_ascii_strncasecmp ("answer", json_reader_get_string_value (reader), 6))
        {
          json_reader_end_member (reader);
          if (json_reader_read_member (reader, "rrname"))
          {
            value = g_utf8_strdown(json_reader_get_string_value (reader), -1);
            g_ptr_array_add (parsed_array, (gpointer)value);

            value = avr_tld_get_domain(correlation->_priv->domains, value);
            if (value != NULL)
            {
              g_ptr_array_add (parsed_array, (gpointer)value);
              g_debug ("Stripped Domain: %s", value);
            }
          }
          json_reader_end_member (reader);
        }
      }
    }
    json_reader_end_member (reader);
    if (json_reader_read_member (reader, "http"))
    {
      if (json_reader_read_member (reader, "hostname"))
      {
        value = g_utf8_strdown(json_reader_get_string_value(reader), -1);
        g_ptr_array_add (parsed_array, (gpointer)value);

        value = avr_tld_get_domain(correlation->_priv->domains, value);
        if (value != NULL)
        {
          g_ptr_array_add (parsed_array, (gpointer)value);
          g_debug ("Stripped Domain: %s", value);
        }
      }
      json_reader_end_member (reader);
    }
    json_reader_end_member (reader);


    break;
  case HOSTNAME:
    // Read "rrname" under "dns"
    if (json_reader_read_member (reader, "dns"))
    {
      if (json_reader_read_member (reader, "type"))
      {
        if (!g_ascii_strncasecmp ("answer", json_reader_get_string_value (reader), 6))
        {
          json_reader_end_member (reader);
          if (json_reader_read_member (reader, "rrname"))
          {
            value = g_utf8_strdown(json_reader_get_string_value (reader), -1);
            g_ptr_array_add (parsed_array, (gpointer)value);
          }
          json_reader_end_member (reader);
        }
      }
    }
    json_reader_end_member (reader);

    // Read "hostname" under "http".
    if (json_reader_read_member (reader, "http"))
    {
      if (json_reader_read_member (reader, "hostname"))
      {
        value = g_utf8_strdown(json_reader_get_string_value (reader), -1);
        g_ptr_array_add (parsed_array, (gpointer)value);
      }
      json_reader_end_member (reader);
    }
    json_reader_end_member (reader);

    break;
  default:
    g_warning("Invalid data type, cannot parse line");
  }

  g_object_unref (reader);

  return (parsed_array);
}

/**
 * _avr_correlation_match_ip_address:
 * @void
 *
 *
 * Returns:
 */
static gchar *
_avr_correlation_match_ip_address (AvrCorrelation * correlation, GPtrArray * parsed_array)
{
  g_return_val_if_fail (AVR_IS_CORRELATION(correlation), NULL);
  g_return_val_if_fail (parsed_array->len > 0, NULL);

  gpointer data = NULL;
  guint i = 0, j = 0;
  GInetAddress * value_inet_addr = NULL;
  GPtrArray * found_array = NULL;
  GHashTable * result_htable = NULL;
  GPtrArray * value_array = NULL;
  GString * result_str = NULL;
  GString * key_str = NULL, * value_str = NULL;

  if ((data = avr_db_ref_data (correlation->_priv->db)) == NULL)
    return (NULL);

  // Start at position 1, since position 0 is the header.
  for (i = 1; i < parsed_array->len; i++)
  {
    // Use '32' for the key mask, as we will deal with IP addresses in IPv4 only.
    value_inet_addr = g_inet_address_new_from_string((gchar *)g_ptr_array_index(parsed_array, i));

    if (value_inet_addr)
    {
      found_array = radix_tree_lookup((RadixTree *)data, g_inet_address_to_bytes(value_inet_addr), 32, NULL);

      if (found_array != NULL)
      {
        if (found_array->len > 0)
        {
          g_debug("Matched IP '%s'", (gchar *)g_ptr_array_index(parsed_array, i));
          if (result_htable == NULL)
            result_htable = g_hash_table_new_full ((GHashFunc)g_str_hash, (GEqualFunc)g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_ptr_array_unref);

          for (j = 1; j < found_array->len; j++)
          {
            key_str = (GString *)g_ptr_array_index (found_array, j);
            if ((value_array = g_hash_table_lookup (result_htable, key_str->str)) != NULL)
            {
              // If a previous pulse was found, replace the value.
              value_str = (GString *)g_ptr_array_index(found_array, 0);
              g_ptr_array_add((GPtrArray *)value_array, (gpointer)g_strdup_printf("%s", value_str->str));
            }
            else
            {
              // If not, add the new one.
              value_array = g_ptr_array_new_with_free_func ((GDestroyNotify)g_free);
              value_str = (GString *)g_ptr_array_index(found_array, 0);
              g_ptr_array_add((GPtrArray *)value_array, (gpointer)g_strdup_printf("%s", value_str->str));
              g_hash_table_insert (result_htable, (gpointer)g_strdup_printf("%s", key_str->str), (gpointer)value_array);
            }
          }
        }

        g_ptr_array_unref (found_array);
      }

      g_object_unref(value_inet_addr);
    }
  }

  avr_db_unref_data (correlation->_priv->db, data);

  if (result_htable != NULL)
  {
    result_str = _avr_correlation_build_list_string(result_htable, value_array);

    g_hash_table_unref (result_htable);
    g_debug("Matched Pulse '%s'", result_str->str);
  }

  return (result_str ? g_string_free (result_str, FALSE) : NULL);
}


/**
 * _avr_correlation_match_string:
 * @void
 *
 *
 * Returns:
 */
static gchar *
_avr_correlation_match_string (AvrCorrelation * correlation, GPtrArray * parsed_array)
{
  g_return_val_if_fail (AVR_IS_CORRELATION(correlation), NULL);
  g_return_val_if_fail (parsed_array->len > 0, NULL);

  gpointer data = NULL;
  guint i = 0, j = 0;
  GPtrArray * found_array = NULL;
  GPtrArray * value_array = NULL;
  GHashTable * result_htable = NULL;
  GString * result_str = NULL;
  gchar * key_str = NULL, * value_str = NULL;

  if ((data = avr_db_ref_data (correlation->_priv->db)) == NULL)
    return (NULL);

  // Start at position 1, since position 0 is the event header.
  for (i = 1; i < parsed_array->len; i++)
  {
    // Remember, this is a pointer to the original value, never free it!
    found_array = (GPtrArray *)g_hash_table_lookup ((GHashTable *)data, g_ptr_array_index(parsed_array, i));

    if (found_array != NULL)
    {
      if (found_array->len > 0)
      {
        if (result_htable == NULL)
          result_htable = g_hash_table_new_full ((GHashFunc)g_str_hash,
                                                 (GEqualFunc)g_str_equal,
                                                 (GDestroyNotify)g_free,
                                                 (GDestroyNotify)g_ptr_array_unref);

        for (j = 1; j < found_array->len; j++)
        {
          key_str = (gchar *)g_ptr_array_index (found_array, j);
          g_debug("key: %s", key_str);
          if ((value_array = g_hash_table_lookup (result_htable, key_str)) != NULL)
          {
            // If a previous pulse was found, replace the value.
            value_str = (gchar *)g_ptr_array_index(found_array, 0);
            g_ptr_array_add((GPtrArray *)value_array, (gpointer)g_strdup_printf("%s", value_str));
          }
          else
          {
            // If not, add the new one.
            value_array = g_ptr_array_new_with_free_func ((GDestroyNotify)g_free);
            value_str = (gchar *)g_ptr_array_index(found_array, 0);
            g_ptr_array_add((GPtrArray *)value_array, (gpointer)g_strdup_printf("%s", value_str));
            g_hash_table_insert (result_htable, (gpointer)g_strdup_printf("%s", key_str), (gpointer)value_array);
          }
        }
      }
    }
  }

  avr_db_unref_data (correlation->_priv->db, data);


  if (result_htable != NULL)
  {
    result_str = _avr_correlation_build_list_string(result_htable, value_array);

    g_hash_table_unref (result_htable);
    g_debug("Matched Pulse '%s'", result_str->str);
  }

  return (result_str ? g_string_free (result_str, FALSE) : NULL);
}


/**
 * _avr_correlation_build_list_string:
 * @void
 *
 *
 * Returns:
 */
static GString *
_avr_correlation_build_list_string(GHashTable *result_htable,
                                   GPtrArray  *value_array)
{
  GHashTableIter result_htable_iter;
  GString * result_str = NULL;
  gpointer key = NULL;
  gpointer value = NULL;
  guint j = 0;

  g_hash_table_iter_init (&result_htable_iter, result_htable);
  while (g_hash_table_iter_next (&result_htable_iter, &key, &value))
  {
    if (result_str == NULL)
      result_str = g_string_new (NULL);
    else
      g_string_append_printf (result_str, ",");

    // Set the Pulse ID.
    g_string_append_printf (result_str, "\"%s\": [", (gchar *)key);

    // Append the IoC list.
    value_array = (GPtrArray *)value;
    for (j = 0; j < value_array->len; j++)
    {
      g_string_append_printf (result_str, "\"%s\"%s", (gchar *)g_ptr_array_index(value_array, j), (j + 1) >= value_array->len ? "" : ",");
    }

    // Close the list.
    g_string_append_printf (result_str, "]");
  }

  // Avoid delivering an unnecessary comma at the end.
  if ((result_str) && (result_str->str[result_str->len - 1] == ','))
    result_str = g_string_truncate(result_str, result_str->len - 1);

  return result_str;
}
