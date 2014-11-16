[1mdiff --git a/firewall.py b/firewall.py[m
[1mindex e4b7e84..c47428d 100644[m
[1m--- a/firewall.py[m
[1m+++ b/firewall.py[m
[36m@@ -131,14 +131,14 @@[m [mclass Firewall:[m
         except Exception, e:[m
             print e , " 1"[m
             return [m
[31m-        print "Source IP: " + packet.src_ip + ", ",[m
[31m-        print "Source port: " + packet.src_port + ", ", [m
[31m-        print "Destination IP: " + packet.dst_ip + ", ",[m
[31m-        print "Destination Port: " + packet.dst_port + ", ",[m
[31m-        print "Length: " + --length-- ", ",[m
[31m-        print "Protocol: " + packet.protocol + ", "[m
[32m+[m[32m        print "Source IP: " , packet.src_ip , ", ",[m
[32m+[m[32m        print "Source port: " , packet.src_port , ", ",[m[41m [m
[32m+[m[32m        print "Destination IP: " , packet.dest_ip , ", ",[m
[32m+[m[32m        print "Destination Port: " , packet.dst_port , ", ",[m
[32m+[m[32m        print "Length: " ,"not yet", ", ",[m
[32m+[m[32m        print "Protocol: " , packet.protocol , ", "[m
         if packet.is_DNS:[m
[31m-            print "DNS Address: " + packet.dns_query + ", "[m
[32m+[m[32m            print "DNS Address: " , packet.dns_query , ", "[m
         return[m
 [m
     #sends packet to respected location[m
[36m@@ -190,13 +190,13 @@[m [mclass Firewall:[m
 [m
     def get_src(self, pkt):[m
         address_byte = pkt[12:16][m
[31m-        unpacked_byte = struct.unpack("!HH", address_byte)[0][m
[32m+[m[32m        unpacked_byte = struct.unpack("!I", address_byte)[0][m
         return unpacked_byte[m
 [m
 [m
     def get_dst(self, pkt):[m
         address_byte = pkt[16:20][m
[31m-        unpacked_byte = struct.unpack("!HH", address_byte)[0][m
[32m+[m[32m        unpacked_byte = struct.unpack("!I", address_byte)[0][m
         return unpacked_byte[m
 [m
     #@packet is the data structure for a packet with our necessary contents[m
[1mdiff --git a/firewall.pyc b/firewall.pyc[m
[1mindex 71812c3..114b109 100644[m
Binary files a/firewall.pyc and b/firewall.pyc differ
