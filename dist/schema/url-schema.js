import { z } from 'zod';
export const urlSchema = z.object({
    url: z.string().optional().refine(value => !value || /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})(\/[\w.-]*)*\/?$/.test(value), {
        message: "Please provide a valid URL",
    })
});
//# sourceMappingURL=url-schema.js.map