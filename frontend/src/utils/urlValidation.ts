import { z } from "zod";

export const urlInputSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, "Please enter a URL to scan.")
    .max(2048, "URL must be 2048 characters or fewer.")
    .refine(
      (val) => {
        try {
          const parsed = new URL(val);
          return parsed.protocol === "http:" || parsed.protocol === "https:";
        } catch {
          return false;
        }
      },
      { message: "Enter a valid URL starting with http:// or https://" },
    ),
});

export type UrlInputFormValues = z.infer<typeof urlInputSchema>;

