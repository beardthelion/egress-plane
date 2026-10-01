export async function loadProfile(): Promise<void> {
  await fetch("/api/profile");
}
