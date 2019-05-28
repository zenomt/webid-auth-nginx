samples
=======
This directory contains a sample configuration file and an ACL root directory
with several sample ACL files.

You can use the sample ACL root directory as-is to see how the auth server
responds to different requests. Permission checks are made independently of
any actual resource retrieval, so you can look for `200`, `401`, and `403`
responses from the auth server whether or not you have corresponding documents
or resources with the same names in your web server's document root.

Be sure to notice the `.acl` files in the `root` and `root/checked` directories,
since they might be hidden in default file listings.
