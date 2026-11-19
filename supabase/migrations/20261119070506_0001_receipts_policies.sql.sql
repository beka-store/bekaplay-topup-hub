/*
# Receipts storage policies

1. Plain-English summary
   Lets anyone (including guests checking out) upload payment receipt images
   into the private `receipts` storage bucket, and lets only store owners read
   them (so owners can verify transfers in the admin panel).

2. Security changes
   - Storage policy on `storage.objects`: INSERT into bucket 'receipts' allowed
     for anon + authenticated.
   - Storage policy: SELECT from 'receipts' only for authenticated owners.
   The bucket itself must exist (created in the dashboard / provisioning).
*/

DROP POLICY IF EXISTS "public_upload_receipts" ON storage.objects;
CREATE POLICY "public_upload_receipts" ON storage.objects FOR INSERT
  TO anon, authenticated WITH CHECK (bucket_id = 'receipts');

DROP POLICY IF EXISTS "owner_read_receipts" ON storage.objects;
CREATE POLICY "owner_read_receipts" ON storage.objects FOR SELECT
  TO authenticated USING (bucket_id = 'receipts' AND public.is_owner());