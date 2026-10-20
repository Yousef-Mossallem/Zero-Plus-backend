// backend/src/modules/organizations/organizations.schema.ts
// ==================================================================
// Zero Plus - Organizations Validation Schema
// ==================================================================

import { z } from 'zod'

export const updateOrganizationSchema = z
  .object({
    name: z
      .string({ invalid_type_error: 'الاسم يجب أن يكون نص' })
      .min(2, { message: 'اسم الشركة يجب أن يكون من حرفين على الأقل' })
      .max(100, { message: 'اسم الشركة طويل جدًا' })
      .optional(),

    slug: z
      .string({ invalid_type_error: 'الـ slug يجب أن يكون نص' })
      .min(2, { message: 'الـ slug يجب أن يكون من حرفين على الأقل' })
      .max(100, { message: 'الـ slug طويل جدًا' })
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, {
        message: 'الـ slug يجب أن يحتوي على حروف صغيرة وأرقام وشرطات فقط',
      })
      .optional(),
  })
  .refine((data) => data.name || data.slug, {
    message: 'يجب إرسال name أو slug على الأقل',
  })

export type UpdateOrganizationInput = z.infer<typeof updateOrganizationSchema>
