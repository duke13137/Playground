# Ubiquitous Language

## IAM relationship model

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **IAM Resource** | An AWS IAM object that can participate in an access relationship, such as a **Role**, **Policy**, **Principal**, or **Instance Profile**. | Resource, object |
| **Role** | An IAM identity that can be assumed by a **Principal** and receives permissions from **Policies**. | IAM role, role resource |
| **CicdRole** | A demo **Role** representing an automation pipeline identity that can delegate a target role to a deployment service. | CiRole, CI role, pipeline role |
| **Principal** | An identity named in a trust policy or resource policy, such as an AWS account, IAM user, IAM role, AWS service, or federated identity. | Actor, subject, identity |
| **Known Principal** | A **Principal** imported from account inventory rather than inferred only from a policy reference. | Internal principal, real principal |
| **Synthetic Principal** | A **Principal** created from a policy reference when the referenced identity is external or absent from inventory. | Placeholder principal, inferred principal |
| **Policy** | A permissions document that can grant, deny, bound, or trust access. | IAM policy, permission document |
| **Managed Policy** | A standalone **Policy** identified by an ARN and attached to one or more IAM identities. | Attached policy, customer policy |
| **Inline Policy** | A **Policy** embedded directly in exactly one owning IAM identity. | Embedded policy, role policy |
| **Permissions Boundary** | A **Policy** that caps the maximum permissions an IAM identity can exercise. | Boundary, permission boundary |
| **Trust Policy** | A **Policy** on a **Role** that defines which **Principals** may assume that role. | Assume role policy, assume role document |
| **Resource Control Policy** | An AWS Organizations policy that sets maximum permissions for supported resources in member accounts. | RCP |
| **Instance Profile** | An IAM container that exposes a **Role** to an EC2 instance. | Profile, EC2 role wrapper |
| **Role Transition** | A potential movement from one principal context to another role context. | Role chain, hop |
| **Role Assumption** | A **Role Transition** where a **Principal** may call `sts:AssumeRole` into a target **Role**. | AssumeRole edge, role hop |
| **Role Delegation** | A **Role Transition** where a **Principal** may call `iam:PassRole` so an AWS service can use a target **Role**. | PassRole edge, service delegation |
| **Delegated Service** | The AWS service principal constrained by `iam:PassedToService` or implied by the destination service. | Passed service, target service |
| **Associated Resource** | The resource constrained by `iam:AssociatedResourceArn` for a **Role Delegation**. | Associated ARN |

## Organization scope

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Organization Scope** | An AWS Organizations root, OU, or account where a **Resource Control Policy** can be attached. | Org node, target |
| **Organizational Unit** | An AWS Organizations container that groups accounts under a parent scope. | OU |
| **Member Account** | An AWS account inside an organization where supported resources may be restricted by **Resource Control Policies**. | Account |

## Policy language

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Policy Document** | The JSON policy body containing a version and one or more **Statements**. | Document, JSON blob |
| **Policy Version** | A versioned body of a **Managed Policy**, one of which is the default version used for authorization. | Version |
| **Statement** | A single IAM policy clause that combines effect, actions, resources, principals, and conditions. | Rule, permission row |
| **Effect** | The statement decision, either allow or deny. | Decision |
| **Action** | An AWS service operation or wildcard pattern named by a statement. | Operation, permission |
| **Action Pattern** | The raw `Action` or `NotAction` string from a policy statement, including wildcards. | Raw action, action string |
| **Expanded Action** | A concrete AWS service action derived from an **Action Pattern** using the AWS service-reference catalog. | Resolved action, normalized action |
| **Resource Pattern** | An ARN or wildcard resource expression named by a statement. | Resource, ARN |
| **Matched Resource** | A known inventory resource derived as a possible match for a **Resource Pattern**. | Resolved resource, expanded resource |
| **Importable Resource** | A non-IAM inventory resource kept in the graph because IAM Access Analyzer or Resource Control Policies support analyzing or restricting it. | Supported resource, tracked resource |
| **Condition** | A predicate that restricts when a **Statement** applies. | Constraint, filter |
| **Condition Key** | A named request-context field used by a **Condition**. | Context key, condition field |
| **Condition Key Pattern** | A parameterized **Condition Key** whose name includes a variable segment such as a tag key. | Dynamic key, templated key |
| **Condition Operator** | The IAM comparison operator used by a **Condition**. | Operator |

## Data perimeter

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Data Perimeter** | A set of preventive controls that constrain access by identity, network, resource ownership, organization membership, and service path. | Perimeter, guardrail |
| **Identity Perimeter Key** | A **Condition Key** that constrains who the requesting principal is or where that principal belongs. | Principal boundary key |
| **Resource Perimeter Key** | A **Condition Key** that constrains the account, organization, or tag ownership of the target resource. | Resource boundary key |
| **Network Perimeter Key** | A **Condition Key** that constrains the network origin or VPC endpoint path of a request. | Network boundary key |
| **Service Perimeter Key** | A **Condition Key** that constrains whether and how AWS services call other AWS services. | Service path key |
| **Request Perimeter Key** | A **Condition Key** that constrains request metadata such as requested Region, source ARN, source account, or requested tags. | Request boundary key |
| **Session Perimeter Key** | A **Condition Key** that constrains the STS session name, external ID, source identity, or transitive tags of a role session. | Session key |
| **Sensitive Condition Key** | A **Condition Key** where AWS warns that wildcard matching has no valid use case. | Sensitive key |
| **Perimeter Condition** | A **Condition** that uses a data-perimeter-relevant **Condition Key**. | Guardrail condition |

## AWS Config provenance

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Configuration Item** | An AWS Config snapshot describing one AWS resource at a capture time. | CI, Config item, snapshot |
| **Current State** | The latest known relationship graph derived from imported configuration items. | Live state, latest snapshot |
| **Provenance** | The link from a normalized relationship or resource back to the **Configuration Item** or **Policy Document** that produced it. | Source, origin |
| **Historical Timeline** | A separate model of how configuration items and relationships changed over time. | History, audit log |

## Analysis goals

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Relationship Analysis** | Querying IAM entities as a graph of principals, roles, policies, statements, actions, resources, and conditions. | Inventory query |
| **Blast Radius** | The set of roles, policies, actions, resources, or principals affected by a permission relationship. | Impact, exposure |
| **Effective Allow** | An allow statement reachable from a role through its managed or inline policies before deny and boundary evaluation. | Effective permission |
| **Authorization Decision** | A final allow or deny result for one request context after applying all IAM evaluation rules. | Effective permission, final access |

## Relationships

- A **Role** has exactly one **Trust Policy**.
- A **Trust Policy** contains one or more **Statements**.
- A **Role Assumption** requires both an identity-side allow for `sts:AssumeRole` and a target **Trust Policy** that trusts the caller.
- A **Role Delegation** requires an identity-side allow for `iam:PassRole` and may name a **Delegated Service** and **Associated Resource** through conditions.
- A **Role Transition** stores evidence statements but is not an **Authorization Decision**.
- A **Statement** may reference zero or more **Principals**, **Actions**, **Resource Patterns**, and **Conditions**.
- A **Condition** references exactly one **Condition Key** and exactly one **Condition Operator**.
- A **Condition Key Pattern** may match many concrete **Condition Keys** in policy documents.
- A **Perimeter Condition** is identified from its **Condition Key**, not from the statement effect alone.
- An **Action Pattern** is source truth; an **Expanded Action** is derived and may change when the AWS service-reference catalog changes.
- A **Resource Pattern** is source truth; a **Matched Resource** is derived and may change when inventory or ARN matching rules change.
- A **Matched Resource** should be imported as an **Importable Resource** only when IAM Access Analyzer or **Resource Control Policy** support makes it relevant.
- A **Principal** is either a **Known Principal** from inventory or a **Synthetic Principal** inferred from a policy reference.
- **CicdRole** may participate in **Role Delegation** when it can call `iam:PassRole` for a target **Role** and **Delegated Service**.
- A **Role** may have zero or more **Managed Policies**.
- A **Role** may have zero or more **Inline Policies**.
- A **Role** may have zero or one **Permissions Boundary**.
- A **Managed Policy** has one or more **Policy Versions**.
- A **Managed Policy** has exactly one default **Policy Version** for current-state analysis.
- A **Resource Control Policy** is a first-class **Policy** attached to one or more **Organization Scopes**.
- A **Member Account** belongs to exactly one current **Organization Scope** in the import model.
- A **Configuration Item** describes exactly one normalized IAM resource in the current import model.
- **Current State** keeps the latest normalized relationships, while **Provenance** keeps links back to source data.
- A **Historical Timeline** is intentionally separate from **Current State** unless temporal analysis becomes a primary goal.
- An **Authorization Decision** is out of scope for the current model unless a request context and full IAM evaluator are added.

## Example dialogue

> **Dev:** "When a **Principal** can assume a **Role**, where do we store that relationship?"
>
> **Domain expert:** "In the **Trust Policy**: the **Role** points to a policy document whose **Statements** reference the trusted **Principals**."
>
> **Dev:** "Do we flatten a **Managed Policy** into the **Role**?"
>
> **Domain expert:** "No. The **Role** points to the **Managed Policy**, and the policy points to its default **Policy Version** and **Policy Document**."
>
> **Dev:** "So for **Blast Radius**, I traverse from **Role** to **Policy**, then to **Statement**, **Action**, and **Resource Pattern**?"
>
> **Domain expert:** "Exactly. Keep the raw **Configuration Item** as **Provenance**, but query the normalized relationship graph."
>
> **Dev:** "Is `iam:PassRole` the same as **Role Assumption**?"
>
> **Domain expert:** "No. `sts:AssumeRole` is **Role Assumption** by a caller; `iam:PassRole` is **Role Delegation** where a **Delegated Service** receives permission to use the role."
>
> **Dev:** "So **CicdRole** can delegate **AdminRole** to ECS without assuming **AdminRole** itself?"
>
> **Domain expert:** "Correct. That is **Role Delegation**, and the **Delegated Service** plus any **Associated Resource** must be shown separately."

## Flagged ambiguities

- "Resource" is overloaded between AWS resources, IAM policy `Resource` elements, and Datalevin entities; use **IAM Resource** for IAM objects and **Resource Pattern** for policy `Resource` values.
- "Condition key" and "condition field" should not be used interchangeably; use **Condition Key** for catalog metadata and **Condition** for a statement occurrence.
- "Perimeter" is vague; use **Identity Perimeter Key**, **Resource Perimeter Key**, **Network Perimeter Key**, **Service Perimeter Key**, or **Request Perimeter Key** when discussing a control dimension.
- "Policy" is overloaded between trust, managed, inline, and boundary usage; use **Trust Policy**, **Managed Policy**, **Inline Policy**, or **Permissions Boundary** when the role of the policy matters.
- "RCP target" should be called **Organization Scope** unless referring specifically to an **Organizational Unit** or **Member Account**.
- "Principal" may refer to an inventoried IAM identity or an external reference found only in a policy; use **Known Principal** or **Synthetic Principal** when that distinction matters.
- "Role chain" is vague; use **Role Assumption** for `sts:AssumeRole` hops and **Role Delegation** for `iam:PassRole` hops.
- "CiRole" should not be used; use **CicdRole** for the demo automation role.
- "Effective permission" can imply full IAM evaluation including explicit deny, boundaries, session policies, SCPs, and resource policies; use **Effective Allow** for the narrower graph query currently modeled.
- "Finding" should not be used for now; the current model stores source relationships and query results, not persisted derived findings.
- "Action" can mean a raw wildcard-bearing policy value or a concrete service action; use **Action Pattern** for source policy text and **Expanded Action** for derived catalog matches.
- "Resource" can mean a raw policy value or an inventory object matched by analysis; use **Resource Pattern** for source policy text and **Matched Resource** for derived inventory matches.
- "Supported resource" is vague; use **Importable Resource** when the resource is in scope because of IAM Access Analyzer or **Resource Control Policy** support.
- "History" can mean AWS Config snapshots or relationship changes; use **Provenance** for source snapshots and **Historical Timeline** for temporal relationship analysis.
