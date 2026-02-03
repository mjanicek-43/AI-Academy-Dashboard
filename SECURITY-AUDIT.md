Executive Summary
The application has a solid foundation based on the SAAS-ARCHITECTURE-RECOMMENDATIONS.md document, with good practices like structured logging and webhook signature verification. However, several critical vulnerabilities were identified that undermine the application's security posture. The most severe issues relate to broken access control, allowing any user to perform administrative actions, and incomplete database security policies that could lead to data breaches.

This audit prioritizes immediate containment of these critical risks, followed by a strategic plan to harden the application and migrate to a more robust authentication provider as requested.

1. Critical & High-Risk Findings
These findings require immediate attention as they pose a significant risk to the application and its data.

🔴 CRITICAL: Broken Access Control in API Authorization
Severity: Critical
File: c:\Users\MartinJanicek\Documents\GitHub\AI-Academy-Dashboard\ai-academy-dashboard\src\lib\api-auth.ts (Lines 88-107)
Description: The requireAdminOrMentor function is intended to protect routes that allow reviewing submissions. However, its logic is flawed: it grants access to any user who is an admin OR has a participantId. Since all students are participants, this effectively allows any student to access mentor-level functionality.
Exploit Scenario: A malicious student could call the /api/review or /api/bulk-review endpoints for any other student's submission. They could approve their own work, reject a rival's work, or view feedback not intended for them, leading to data integrity and confidentiality loss.
Recommended Fix: The function must be updated to check for an explicit administrative or mentor role. I will add a check for a new is_mentor boolean flag in the participants table, alongside the existing is_admin check.
🔴 CRITICAL: Incomplete Row-Level Security (RLS) Policies
Severity: Critical
File: c:\Users\MartinJanicek\Documents\GitHub\AI-Academy-Dashboard\ai-academy-dashboard\supabase\migrations\20260131100000_operation_ai_ready_europe.sql
Description: The architecture review document states that RLS write policies were implemented, but the provided migration file only contains permissive SELECT policies (USING (true)). It is missing policies for INSERT, UPDATE, and DELETE operations based on the authenticated user's ID (auth.uid()). This creates a binary and dangerous situation: either API routes are using the master service_role key to bypass RLS for user-specific actions (a major security flaw), or users are unable to write any data.
Exploit Scenario: If API routes use the service role key to perform actions on behalf of a user, a flaw in an API endpoint (e.g., a missing ownership check) would allow an attacker to modify or delete any record in a table, as RLS provides no backup protection.
Recommended Fix: A new database migration must be created to implement strict, ownership-based RLS policies for all tables containing user data. Users should only be able to modify their own records.
🟠 HIGH: Stored Cross-Site Scripting (XSS) via Markdown
Severity: High
File: c:\Users\MartinJanicek\Documents\GitHub\AI-Academy-Dashboard\ai-academy-dashboard\src\app\api\webhook\github\route.ts (Line 131)
Description: The GitHub webhook handler fetches the content of README.md files and stores it directly in the database (readme_content). This content is likely rendered on the frontend for mentors to review. The application does not perform any sanitization on this HTML/Markdown content.
Exploit Scenario: A student can embed a malicious script (e.g., <img src=x onerror=alert(document.cookie)>) in their README.md file. When a mentor or admin views the submission, the script executes in their browser, potentially stealing their session token, performing actions on their behalf (like approving all submissions), or redirecting them to a phishing site.
Recommended Fix: Sanitize the readmeContent on the server-side before it is stored in the database or before it is rendered on the client. Using a library like DOMPurify is highly recommended.
2. Recommended Fixes & Code Changes
Here are the immediate code changes required to remediate the critical and high-risk findings.

Fix for Broken Access Control (api-auth.ts)
This change introduces a proper role check for mentors. You will need to add an is_mentor boolean column to your participants table in Supabase.

api-auth.ts
-4
+4
 Show full code block 
    // Get participant details
    const { data: participant } = await supabase
      .from('participants')
      .select('id, is_admin')
      .select('id, is_admin, is_mentor')
      .eq('email', user.email)
      .single();

      id: user.id,
      email: user.email || '',
      isAdmin: participant?.is_admin || false,
      isMentor: participant?.is_mentor || false, // Add isMentor property
      participantId: participant?.id,
    };

    return authResult;
  }

  // For now, all authenticated users with participant records can review
  // In production, you'd want a separate mentor role
  if (!authResult.user.participantId && !authResult.user.isAdmin) {
  // User must be an admin or a designated mentor.
  if (!authResult.user.isAdmin && !authResult.user.isMentor) {
    logSecurityEvent('forbidden', {
      userId: authResult.user.id,
      path: request.nextUrl.pathname,

New Migration File for RLS Write Policies
This is a new migration file that establishes baseline ownership policies. You should create it under /supabase/migrations/.

New file: YYYYMMDD_add_rls_write_policies.sql
+31
 Show full code block 
-- Migration: Add RLS Write Policies
-- Description: Secures write operations (INSERT, UPDATE, DELETE) for key tables.

-- ============================================================================
-- SUBMISSIONS
-- ============================================================================

-- 1. Users can only insert submissions for themselves.
CREATE POLICY "Allow own submission insert" ON submissions
  FOR INSERT WITH CHECK (participant_id = (SELECT id FROM participants WHERE user_id = auth.uid()));

-- 2. Users can only update their own submissions.
CREATE POLICY "Allow own submission update" ON submissions
  FOR UPDATE USING (participant_id = (SELECT id FROM participants WHERE user_id = auth.uid()));

-- 3. Nobody can delete submissions (recommended: use a status field instead).
-- If deletion is required, enable this policy for admins only.
-- CREATE POLICY "Allow admin delete" ON submissions FOR DELETE USING (is_admin(auth.uid()));


-- ============================================================================
-- PARTICIPANTS
-- ============================================================================

-- 1. Users can view all participants (as per existing public read policy).

-- 2. Users can only update their own participant record.
CREATE POLICY "Allow own participant update" ON participants
  FOR UPDATE USING (id = (SELECT id FROM participants WHERE user_id = auth.uid()));

-- NOTE: Add similar ownership-based policies for other tables like `task_force_members` as needed.

3. AuthZ/AuthN Hardening with Clerk
As requested, here is a plan to migrate from Supabase's built-in auth to Clerk. Clerk provides more comprehensive multi-factor authentication, user management, and organization controls out-of-the-box.

Step 1: Install Clerk and Update Environment
bash
npm install @clerk/nextjs
Add the following to your environment variables:

plaintext
 Show full code block 
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_...
CLERK_SECRET_KEY=sk_...
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
NEXT_PUBLIC_CLERK_SIGN_UP_URL=/sign-up
NEXT_PUBLIC_CLERK_AFTER_SIGN_IN_URL=/
NEXT_PUBLIC_CLERK_AFTER_SIGN_UP_URL=/
Step 2: Update Middleware
Replace the Supabase session logic in middleware.ts with Clerk's authMiddleware. This centralizes route protection.

middleware.ts
-67
+14
 Show full code block 
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { logSecurityEvent, generateCorrelationId } from '@/lib/logger';
import { authMiddleware } from '@clerk/nextjs';

// ============================================================================
// Rate Limiting Configuration
}

// ============================================================================
// Supabase Session Refresh
// ============================================================================

async function updateSession(request: NextRequest): Promise<NextResponse> {
  // Create a response that we'll modify
  let response = NextResponse.next({
    request: {
      headers: request.headers,
    },
  });

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // If env vars are missing, just continue without session refresh
  if (!supabaseUrl || !supabaseAnonKey) {
    return response;
  }

  const supabase = createServerClient(
    supabaseUrl,
    supabaseAnonKey,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          // Update request cookies
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          // Create new response with updated request
          response = NextResponse.next({
            request: {
              headers: request.headers,
            },
          });
          // Set cookies on the response
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // This refreshes the session if expired - REQUIRED for Server Components
  // https://supabase.com/docs/guides/auth/server-side/nextjs
  await supabase.auth.getUser();

  return response;
}

// ============================================================================
// Middleware Function
// ============================================================================

export async function middleware(request: NextRequest) {
export default authMiddleware({
  // Make all routes public by default. We will protect them individually.
  publicRoutes: ["/.*"],

  async afterAuth(auth, request) {
  const { pathname } = request.nextUrl;

  // Skip middleware completely for static files

  // Generate correlation ID for request tracing
  const correlationId = generateCorrelationId();

  // IMPORTANT: Refresh Supabase session for ALL routes (pages and API)
  // This ensures the session cookie is refreshed before it expires
  let response = await updateSession(request);
  const response = NextResponse.next();

  // Get client IP for rate limiting
  const clientIp = getClientIp(request);
  // Add correlation ID and security headers to all responses
  response.headers.set('X-Correlation-Id', correlationId);
  return addSecurityHeaders(response);
}
  }
});

// Configure which routes the middleware runs on
export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder files (images, icons, etc.)
     * - api/trpc (tRPC routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
    "/((?!api/trpc|_next/static|_next/image|favicon.ico).*)",
  ],
};

Step 3: Protect Routes and Check Roles
You can now protect pages and API routes easily.

Example: Protecting an Admin Page

typescript
 Show full code block 
// src/app/admin/page.tsx
import { auth } from "@clerk/nextjs";
import { redirect } from "next/navigation";

export default function AdminPage() {
  const { sessionClaims } = auth();

  // If the user does not have the admin role, redirect them
  if (sessionClaims?.metadata?.role !== "admin") {
    redirect("/");
  }

  return (
    <div>
      <h1>Admin Dashboard</h1>
      {/* Admin content here */}
    </div>
  );
}
Example: Protecting an API Route

This would replace the logic in api-auth.ts.

typescript
 Show full code block 
// src/app/api/review/route.ts
import { auth } from '@clerk/nextjs';
import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const { userId, sessionClaims } = auth();

  // Check for user authentication
  if (!userId) {
    return new NextResponse("Unauthorized", { status: 401 });
  }

  // Check for admin or mentor role from Clerk's session metadata
  const userRole = sessionClaims?.metadata?.role;
  if (userRole !== 'admin' && userRole !== 'mentor') {
    return new NextResponse("Forbidden", { status: 403 });
  }

  // ... proceed with review logic
  
  return NextResponse.json({ success: true });
}
4. Security Hardening Plan
This is a prioritized timeline to address all findings.

Phase 1: Immediate Containment (Next 24 Hours)
Fix Access Control:
Action: Add the is_mentor column to the participants table in Supabase.
Action: Apply the diff for src/lib/api-auth.ts to fix the requireAdminOrMentor function immediately. This contains the most critical vulnerability.
Mitigate XSS Risk:
Action: Install a server-side sanitization library (npm install sanitize-html @types/sanitize-html).
Action: In src/app/api/webhook/github/route.ts, before the upsert call, add code to clean the readmeContent.
typescript
 Show full code block 
import sanitizeHtml from 'sanitize-html';
// ...
let points = assignmentFull?.max_points || 15;
if (assignmentFull?.due_at && new Date(assignmentFull.due_at) < now) {
  points = Math.floor(points * 0.5); // 50% for late
}

// Sanitize README content before storing
const sanitizedReadme = sanitizeHtml(readmeContent, {
  allowedTags: sanitizeHtml.defaults.allowedTags.concat([ 'h1', 'h2' ]),
  allowedAttributes: {} // Remove all attributes to be safe
});

// Upsert submission
const { data: submission, error: sError } = await supabase
  .from('submissions')
  .upsert({
      //...
      readme_content: sanitizedReadme, // Use sanitized content
      //...
  })
Phase 2: Foundational Security (Next 7 Days)
Implement RLS Write Policies:
Action: Create and run the new migration file (YYYYMMDD_add_rls_write_policies.sql) to enforce data ownership at the database level.
Deploy Content-Security-Policy (CSP):
Action: Add a strict CSP header in next.config.js. This is a powerful defense against XSS.
javascript
 Show full code block 
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src * blob: data:; media-src 'none'; connect-src *; font-src 'self';",
  },
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
Note: This CSP is a starting point and may need to be adjusted based on your specific needs (e.g., for Supabase connections, image providers).
Upgrade Rate Limiting:
Action: Provision an Upstash Redis database.
Action: Refactor the checkRateLimit function in middleware.ts to use the Redis client instead of the in-memory Map. This ensures consistent rate limiting across all server instances.
Phase 3: Strategic Overhaul (Next 30 Days)
Migrate to Clerk:
Action: Plan and execute the migration from Supabase Auth to Clerk, following the steps outlined in section 3. This involves updating the frontend to use Clerk's components for sign-in/sign-up and refactoring all API routes and server components to use auth() instead of requireAuth.
Action: Decommission the custom api-auth.ts file once the migration is complete.
This comprehensive plan will not only fix the existing critical vulnerabilities but also significantly elevate the overall security and robustness of the AI Academy Dashboard.