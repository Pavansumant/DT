# (DT) for HCL Software

**Dependency-Track (DT)** will be used as HCL Software's centralized platform for **Software Bill of Materials (SBOM)** management and open-source component visibility.

Dependency-Track enhances our software supply chain security by providing continuous visibility into the software components used across our products and identifying known vulnerabilities affecting those components. As part of our Product Security program, Dependency-Track serves as the primary platform for tracking SBOMs and monitoring software composition risk across HCL Software products.

## Why Dependency-Track?

Dependency-Track provides a centralized inventory of software components and enables both Product Security and development teams to better understand and manage open-source risk throughout the software development lifecycle.

### Key Capabilities

Dependency-Track enables HCL Software teams to:

- Upload and manage **CycloneDX Software Bill of Materials (SBOMs)**.
- Continuously identify known vulnerabilities affecting software components.
- Monitor component risk across product versions.
- View detailed component inventories and associated vulnerability information.
- Support automated SBOM ingestion through APIs and command-line tools.

### Benefits for Product Security

From a Product Security perspective, Dependency-Track provides centralized visibility into vulnerabilities across HCL Software products, allowing the Product Security team to:

- Monitor software supply chain exposure.
- Prioritize vulnerability remediation.
- Report on overall software supply chain risk.

### Benefits for Product Teams

Development teams can:

- Upload and maintain SBOMs for their assigned products.
- View vulnerabilities affecting their own applications.
- Better understand software composition risk throughout the development lifecycle.

## Access Model

Dependency-Track follows the **principle of least privilege**.

- Product teams are granted access only to their assigned products and projects.
- Teams can create projects and upload SBOMs for the products they own.
- Administrative privileges are not required for normal SBOM management activities.
- Authentication is performed using **Okta Single Sign-On (SSO)**.

---

# Dependency-Track SBOM Management

HCL Software supports two methods for importing **Software Bill of Materials (SBOMs)** into Dependency-Track:

1. **Dependency-Track Web Interface (Manual Upload)** – Manually create projects and upload SBOMs through the Dependency-Track web interface.
2. **Dependency-Track SBOM Importer (Automation)** – Automatically create projects (when necessary) and upload one or more SBOMs using the CLI tool.

Product teams can upload SBOMs for their assigned products without requiring Dependency-Track administrative access. Access is limited to the products assigned to the user.

---

# 1. Dependency-Track Web Interface (Manual Upload)

This option allows users to manually create projects and upload SBOMs through the Dependency-Track web interface.

## Login

All users must authenticate using **Okta Single Sign-On (SSO)**.

For security reasons, username/password authentication is not supported. All product teams should select **Log in with Okta** and authenticate using their HCL Software credentials.

## Manual Upload Process

### Step 1 – Login

1. Open the Dependency-Track web application.
2. Select **Log in with Okta**.
3. Authenticate using your HCL Software credentials.

### Step 2 – Navigate to Projects

1. Open the **Projects** page.
2. Select **Create Project**, or open an existing project.

### Step 3 – Create the Project

Provide the following information.

#### Required Fields

- Project Name
- Classifier (Application, Library, Framework, Container, etc.)
- Team
- Project Collection Logic
  - **None** – Standalone project
  - **Parent** – Parent/Child relationship

#### Optional Fields

- Version
- Latest Version
- Parent Project
- Description
- Tags

After verifying the information, select **Create**.

### Step 4 – Upload the SBOM

1. Open the project.
2. Select the **Components** tab.
3. Click **Upload BOM**.
4. Select your **CycloneDX JSON** SBOM.
5. Upload the file.
6. Wait for Dependency-Track to complete processing.

Repeat these steps for each project or application.

---

# 2. Dependency-Track SBOM Importer (Automation)

For teams wishing to automate SBOM uploads, HCL Software provides the **Dependency-Track SBOM Importer**.

The importer automatically creates projects (when necessary) and uploads one or more SBOMs directly into Dependency-Track.

## Key Features

- Automatically creates projects if they do not exist.
- Supports uploading multiple SBOM files in a single execution.
- Reads SBOM metadata to determine project name, version, and tags.
- Creates the following hierarchy:

```
Product Family → Product → Version (SBOM)
```

- Supports standard Unix command-line conventions.
- Available as both a Python CLI and Docker image.

---

# Requesting an API Key

The automated importer requires a **Dependency-Track API key**.

Since users authenticate through **Okta SSO**, API keys are issued only by the **Dependency-Track Administration Team**.

## Request Process

1. Log in to Dependency-Track using **Okta**.
2. Verify you can access your assigned project(s).
3. Send an email to **supplychain-dt@hcl-software.com** requesting an API key.
4. Include:
   - Product Family
   - Your HCL Software email address
5. After approval:
   - The API key will be securely provided.
   - Instructions for uploading SBOMs using the API will also be provided.
6. Configure the API key with the SBOM Importer script through `.env` or CLI.

## Requirements

- Python 3.10 or later
- Docker
- Dependency Track API credentials


## Setup

1. **Environment Variables**: The script can use credentials from a `.env` file.The script requires URL and API Key for authentication.

   Create a `.env` file in the root directory and add the following:

   ```bash
   DT_URL="your-dependency-track-url"
   DT_API_KEY = "your_API_key"
   ```

   Replace `your-dependency-track-url` with your Dependency-Track server URL and 
   `your_API_key` with your API credentials.

### Alternative: Pass Credentials via Command Line

Instead of using a `.env` file, you can provide credentials directly:

```
--url <your org url>
--api-key <your API key>
```

## Installation

### Python Package Installation

1. **Install `uv`**

```bash
pip install uv
```

2. **Create Virtual environment**

```bash
uv sync
```
Ensures all dependencies from `pyproject.toml` are installed in UV’s environment.

3. **Build the project**

```bash
uv build
```

Creates distribution files in the `dist/` folder (`.whl` and `.tar.gz`).


4. **Run the dt-upload**

###  Using `.env` in the project root:

```bash
uv run dt-upload --help
```

### Passing credentials explicitly via CLI:

```bash
uv run dt-upload \
  --url <your-dependency-track-url> \
  --api-key your_API_key \
  --help

uv run dt-upload \
  --url <your-dependency-track-url> \
  --api-key your_API_key \
  --family "MyFamily" \
  --product "MyProduct" \
  --version "1.0.0" \
  file1.json file2.json
```
### Docker Installation

1. **Build the Docker image**:

```bash
docker build -t dt-upload .
```

2. **Verify installation**:

```bash
docker run dt-upload --help
```


### Command Line Arguments

*  `--url`: Dependency-Track server URL.
*  `--api-key`: Dependency Track API key.
* `--family`: Specify product family (required).    
* `--product`: Specify product name (required).
* `--version`: Specify product version (required).
* `files`: One or more CycloneDX JSON SBOM files to upload. These are positional arguments, listed after the flags.

### Example Usage

### Python CLI

#### 1. **Upload SBOMs for Specific Product Family,Product,Version**:

**Case A — Using `.env` file in project root**

```bash
uv run dt-upload --family "MyFamily" --product "MyProduct" --version "1.0.0" file1.json file2.json
```
**Case B — Passing credentials explicitly via CLI**

```bash
uv run dt-upload \
  --url <your-dependency-track-url> \
  --api-key your_API_key \
  --family "MyFamily" \
  --product "MyProduct" \
  --version "1.0.0" file1.json file2.json
```


### Docker CLI

#### 1. **Upload SBOMs for Specific Product Family,Product,Version**:

```bash
docker run --env-file /path/to/.env \
  -v /path/to/sboms:/data \
  -w /data \
  dt-upload \
  --family "MyFamily" \
  --product "MyProduct" \
  --version "1.0.0" \
  file1.json file2.json
```

## Troubleshooting

* **Authentication Errors**: Ensure the Dependency-Track API key and URL are correct and provided either through the .env file or the `--api-key` and `--url` command-line options.
* **SBOM Not Uploaded**: Confirm the file exists, is valid JSON, and the Dependency-Track server is reachable.
