# IAM Relationship Analysis

This context models AWS IAM and related AWS Organizations facts as a queryable relationship graph. It exists to answer blast-radius and provenance questions without claiming to be a full IAM authorization evaluator.

## Language

**IAM Resource**:
An AWS IAM object that participates in access relationships, such as a **Role**, **Policy**, **Principal**, or **Instance Profile**.
_Avoid_: Resource, object

**Role**:
An IAM identity that can be assumed by a **Principal** and receives permissions from **Policies**.
_Avoid_: IAM role, role resource

**CicdRole**:
A demo **Role** representing an automation pipeline identity that can delegate a target role to a deployment service.
_Avoid_: CiRole, CI role, pipeline role

**Principal**:
An identity named in a trust policy or resource policy, such as an AWS account, IAM user, IAM role, AWS service, or federated identity.
_Avoid_: Actor, subject, identity

**Known Principal**:
A **Principal** imported from account inventory rather than inferred only from a policy reference.
_Avoid_: Internal principal, real principal

**Synthetic Principal**:
A **Principal** created from a policy reference when the referenced identity is external or absent from inventory.
_Avoid_: Placeholder principal, inferred principal

**Policy**:
A permissions document that can grant, deny, bound, or trust access.
_Avoid_: IAM policy, permission document

**Managed Policy**:
A standalone **Policy** identified by an ARN and attached to one or more IAM identities.
_Avoid_: Attached policy, customer policy

**Inline Policy**:
A **Policy** embedded directly in exactly one owning IAM identity.
_Avoid_: Embedded policy, role policy

**Permissions Boundary**:
A **Policy** that caps the maximum permissions an IAM identity can exercise.
_Avoid_: Boundary, permission boundary

**Trust Policy**:
A **Policy** on a **Role** that defines which **Principals** may assume that role.
_Avoid_: Assume role policy, assume role document

**Resource Control Policy**:
An AWS Organizations policy that sets maximum permissions for supported resources in member accounts.
_Avoid_: RCP

**Instance Profile**:
An IAM container that exposes a **Role** to an EC2 instance.
_Avoid_: Profile, EC2 role wrapper

**Role Transition**:
A derived analytical relationship describing potential movement from one principal context to another role context.
_Avoid_: Role chain, hop

**Role Assumption**:
A **Role Transition** where a **Principal** may call `sts:AssumeRole` into a target **Role**.
_Avoid_: AssumeRole edge, role hop

**Role Delegation**:
A **Role Transition** where a **Principal** may call `iam:PassRole` so an AWS service can use a target **Role**.
_Avoid_: PassRole edge, service delegation

**Delegated Service**:
The AWS service principal constrained by `iam:PassedToService` or implied by the destination service.
_Avoid_: Passed service, target service

**Associated Resource**:
The resource constrained by `iam:AssociatedResourceArn` for a **Role Delegation**.
_Avoid_: Associated ARN

**Organization Scope**:
An AWS Organizations root, OU, or account where a **Resource Control Policy** can be attached.
_Avoid_: Org node, target

**Organizational Unit**:
An AWS Organizations container that groups accounts under a parent scope.
_Avoid_: OU

**Member Account**:
An AWS account inside an organization where supported resources may be restricted by **Resource Control Policies**.
_Avoid_: Account

**Policy Document**:
The JSON policy body containing a version and one or more **Statements**.
_Avoid_: Document, JSON blob

**Policy Version**:
A versioned body of a **Managed Policy**, one of which is the default version used for current-state authorization analysis.
_Avoid_: Version

**Statement**:
A single IAM policy clause that combines effect, actions, resources, principals, and conditions.
_Avoid_: Rule, permission row

**Effect**:
The statement decision, either allow or deny.
_Avoid_: Decision

**Action**:
An AWS service operation or wildcard pattern named by a statement.
_Avoid_: Operation, permission

**Action Pattern**:
The raw `Action` or `NotAction` string from a policy statement, including wildcards.
_Avoid_: Raw action, action string

**Expanded Action**:
A concrete AWS service action derived from an **Action Pattern** using the AWS service-reference catalog.
_Avoid_: Resolved action, normalized action

**Resource Pattern**:
An ARN or wildcard resource expression named by a statement.
_Avoid_: Resource, ARN

**Matched Resource**:
A known inventory resource derived as a possible match for a **Resource Pattern**.
_Avoid_: Resolved resource, expanded resource

**Importable Resource**:
A non-IAM inventory resource kept in the graph because IAM Access Analyzer or **Resource Control Policies** support analyzing or restricting it.
_Avoid_: Supported resource, tracked resource

**Condition**:
A predicate that restricts when a **Statement** applies.
_Avoid_: Constraint, filter

**Condition Key**:
A named request-context field used by a **Condition**.
_Avoid_: Context key, condition field

**Condition Key Pattern**:
A parameterized **Condition Key** whose name includes a variable segment such as a tag key.
_Avoid_: Dynamic key, templated key

**Condition Operator**:
The IAM comparison operator used by a **Condition**.
_Avoid_: Operator

**Data Perimeter**:
A set of preventive controls that constrain access by identity, network, resource ownership, organization membership, and service path.
_Avoid_: Perimeter, guardrail

**Identity Perimeter Key**:
A **Condition Key** that constrains who the requesting principal is or where that principal belongs.
_Avoid_: Principal boundary key

**Resource Perimeter Key**:
A **Condition Key** that constrains the account, organization, or tag ownership of the target resource.
_Avoid_: Resource boundary key

**Network Perimeter Key**:
A **Condition Key** that constrains the network origin or VPC endpoint path of a request.
_Avoid_: Network boundary key

**Service Perimeter Key**:
A **Condition Key** that constrains whether and how AWS services call other AWS services.
_Avoid_: Service path key

**Request Perimeter Key**:
A **Condition Key** that constrains request metadata such as requested Region, source ARN, source account, or requested tags.
_Avoid_: Request boundary key

**Session Perimeter Key**:
A **Condition Key** that constrains the STS session name, external ID, source identity, or transitive tags of a role session.
_Avoid_: Session key

**Sensitive Condition Key**:
A **Condition Key** where AWS warns that wildcard matching has no valid use case.
_Avoid_: Sensitive key

**Perimeter Condition**:
A **Condition** that uses a data-perimeter-relevant **Condition Key**.
_Avoid_: Guardrail condition

**Configuration Item**:
An AWS Config snapshot describing one AWS resource at a capture time.
_Avoid_: CI, Config item, snapshot

**Resource Observation**:
One imported observation of an AWS resource, usually represented by a **Configuration Item**.
_Avoid_: Config version, resource version

**Current State**:
The latest known relationship graph derived from imported configuration items and policy documents.
_Avoid_: Live state, latest snapshot

**Provenance**:
The link from a normalized relationship or resource back to the **Configuration Item** or **Policy Document** that produced it.
_Avoid_: Source, origin

**Historical Timeline**:
The transaction-time history of how imported facts and derived relationships changed across database states.
_Avoid_: History, audit log

**Relationship Analysis**:
Querying IAM entities as a graph of principals, roles, policies, statements, actions, resources, and conditions.
_Avoid_: Inventory query

**Blast Radius**:
The set of roles, policies, actions, resources, or principals affected by a permission relationship.
_Avoid_: Impact, exposure

**Effective Allow**:
An allow statement reachable from a role through its managed or inline policies before deny and boundary evaluation.
_Avoid_: Effective permission

**Authorization Decision**:
A final allow or deny result for one request context after applying all IAM evaluation rules.
_Avoid_: Effective permission, final access

## Relationships

- A **Role** has exactly one **Trust Policy**.
- A **Trust Policy** contains one or more **Statements**.
- A **Role Assumption** requires both an identity-side allow for `sts:AssumeRole` and a target **Trust Policy** that trusts the caller.
- A **Role Delegation** requires an identity-side allow for `iam:PassRole` and may name a **Delegated Service** and **Associated Resource** through conditions.
- A **Role Transition** is derived from source **Statements** and is not an **Authorization Decision**.
- A **Statement** may reference zero or more **Principals**, **Action Patterns**, **Resource Patterns**, and **Conditions**.
- A **Condition** references exactly one **Condition Key** and exactly one **Condition Operator**.
- A **Condition Key Pattern** may match many concrete **Condition Keys** in policy documents.
- A **Perimeter Condition** is identified from its **Condition Key**, not from the statement effect alone.
- An **Expanded Action** is derived from an **Action Pattern** and may change when the AWS service-reference catalog changes.
- A **Matched Resource** is derived from a **Resource Pattern** and may change when inventory or ARN matching rules change.
- A **Matched Resource** should be imported as an **Importable Resource** only when IAM Access Analyzer or **Resource Control Policy** support makes it relevant.
- A **Principal** is either a **Known Principal** from inventory or a **Synthetic Principal** inferred from a policy reference.
- **CicdRole** may participate in **Role Delegation** when it can call `iam:PassRole` for a target **Role** and **Delegated Service**.
- A **Role** may have zero or more **Managed Policies**, zero or more **Inline Policies**, and zero or one **Permissions Boundary**.
- A **Managed Policy** has one or more **Policy Versions** and exactly one default **Policy Version** for current-state analysis.
- A **Resource Control Policy** is a first-class **Policy** attached to one or more **Organization Scopes**.
- A **Member Account** belongs to exactly one current **Organization Scope** in the import model.
- A **Resource Observation** describes exactly one normalized IAM resource at one capture time.
- A **Configuration Item** is a kind of **Resource Observation** from AWS Config.
- **Current State** is the latest graph; **Historical Timeline** is the queryable sequence of prior graph states.
- An **Authorization Decision** is out of scope unless a request context and full IAM evaluator are added.

## Example dialogue

> **Dev:** "When a **Principal** can assume a **Role**, where do we store that relationship?"
>
> **Domain expert:** "As a **Role Assumption** backed by evidence from both a permissions **Statement** and a **Trust Policy** statement."
>
> **Dev:** "Do we flatten a **Managed Policy** into the **Role**?"
>
> **Domain expert:** "No. The **Role** points to the **Managed Policy**, and the policy points to its default **Policy Version** and **Policy Document**."
>
> **Dev:** "If the default **Policy Version** changes, do we overwrite the old document?"
>
> **Domain expert:** "No. The latest **Current State** points at the new default version, and the **Historical Timeline** can still answer what the graph looked like before the transaction."
>
> **Dev:** "Is `iam:PassRole` the same as **Role Assumption**?"
>
> **Domain expert:** "No. `sts:AssumeRole` is **Role Assumption** by a caller; `iam:PassRole` is **Role Delegation** where a **Delegated Service** receives permission to use the role."

## Flagged Ambiguities

- "Resource" is overloaded between AWS resources, IAM policy `Resource` elements, and database entities; use **IAM Resource** for IAM objects and **Resource Pattern** for policy `Resource` values.
- "Condition key" and "condition field" should not be used interchangeably; use **Condition Key** for catalog metadata and **Condition** for a statement occurrence.
- "Perimeter" is vague; use **Identity Perimeter Key**, **Resource Perimeter Key**, **Network Perimeter Key**, **Service Perimeter Key**, **Request Perimeter Key**, or **Session Perimeter Key** when discussing a control dimension.
- "Policy" is overloaded between trust, managed, inline, permissions boundary, and resource control usage; use the precise policy term when the role matters.
- "RCP target" should be called **Organization Scope** unless referring specifically to an **Organizational Unit** or **Member Account**.
- "Principal" may refer to an inventoried IAM identity or an external reference found only in a policy; use **Known Principal** or **Synthetic Principal** when that distinction matters.
- "Role chain" is vague; use **Role Assumption** for `sts:AssumeRole` hops and **Role Delegation** for `iam:PassRole` hops.
- "CiRole" should not be used; use **CicdRole** for the demo automation role.
- "Effective permission" can imply full IAM evaluation; use **Effective Allow** for the narrower graph query currently modeled.
- "Finding" should not be used for now; the current model stores source relationships and query results, not persisted derived findings.
- "Action" can mean a raw wildcard-bearing policy value or a concrete service action; use **Action Pattern** for source policy text and **Expanded Action** for derived catalog matches.
- "Resource" can mean a raw policy value or an inventory object matched by analysis; use **Resource Pattern** for source policy text and **Matched Resource** for derived inventory matches.
- "Supported resource" is vague; use **Importable Resource** when the resource is in scope because of IAM Access Analyzer or **Resource Control Policy** support.
- "Config resource version" is vague; use **Resource Observation** for an imported resource snapshot and **Historical Timeline** for database states across imports.
- "History" can mean AWS Config snapshots, policy-document versions, or database transaction history; use **Resource Observation**, **Policy Version**, or **Historical Timeline** as appropriate.
