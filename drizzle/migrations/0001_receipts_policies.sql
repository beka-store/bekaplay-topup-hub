CREATE POLICY "public_upload_receipts" ON storage.objects FOR INSERT
  TO anon, authenticated WITH CHECK (bucket_id = 'receipts');

CREATE POLICY "owner_read_receipts" ON storage.objects FOR SELECT
  TO authenticated USING (bucket_id = 'receipts' AND public.is_owner());