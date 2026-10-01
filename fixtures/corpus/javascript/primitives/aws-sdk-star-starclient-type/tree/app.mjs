import { S3Client } from "@aws-sdk/client-s3";

export function probe() {
  return new S3Client();
}
