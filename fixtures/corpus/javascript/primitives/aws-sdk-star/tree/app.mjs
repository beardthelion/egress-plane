import { paginateListObjectsV2 } from "@aws-sdk/client-s3";

export function probe() {
  return paginateListObjectsV2();
}
