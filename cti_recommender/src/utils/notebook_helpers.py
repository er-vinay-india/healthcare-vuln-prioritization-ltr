"""
Helper utilities for Jupyter notebooks
Provides functions for external output management
"""
from pathlib import Path
from typing import Optional
from IPython.display import HTML, display
import warnings
import pandas as pd


def _prepare_dataframe_for_export(df):
    """Return a CSV-friendly DataFrame while preserving semantic index labels."""
    export_df = df.copy()

    if isinstance(export_df.columns, pd.MultiIndex):
        export_df.columns = [
            "_".join(str(part) for part in col if str(part) and str(part) != "nan")
            for col in export_df.columns.to_flat_index()
        ]

    default_index = pd.RangeIndex(start=0, stop=len(export_df), step=1)
    if not export_df.index.equals(default_index):
        index_name = export_df.index.name or 'row_label'
        export_df = export_df.reset_index()
        if export_df.columns[0] == 'index':
            export_df = export_df.rename(columns={'index': index_name})

    return export_df

def save_plot(fig, name: str, subdir: str = 'plots', show_link: bool = True):
    """
    Save Plotly/Matplotlib figure externally and optionally display link
    
    Args:
        fig: Plotly figure object or matplotlib figure
        name: Filename (without extension)
        subdir: Subdirectory under outputs/ (default: 'plots')
        show_link: Whether to display a link to the saved file
    
    Returns:
        HTML link object if show_link=True, else None
    """
    output_dir = Path('outputs') / subdir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Detect figure type and save accordingly
    fig_type = type(fig).__name__
    
    if 'plotly' in fig_type.lower() or hasattr(fig, 'write_html'):
        # Plotly figure
        output_path = output_dir / f'{name}.html'
        fig.write_html(output_path)
    elif 'matplotlib' in str(type(fig).__module__) or hasattr(fig, 'savefig'):
        # Matplotlib figure
        output_path = output_dir / f'{name}.png'
        fig.savefig(output_path, dpi=150, bbox_inches='tight')
    else:
        warnings.warn(f"Unknown figure type: {fig_type}. Attempting HTML export.")
        output_path = output_dir / f'{name}.html'
        if hasattr(fig, 'write_html'):
            fig.write_html(output_path)
        else:
            raise ValueError(f"Cannot save figure of type {fig_type}")
    
    if show_link:
        # If output_path is already relative, use it; otherwise compute relative path
        if output_path.is_absolute():
            try:
                rel_path = output_path.relative_to(Path.cwd())
            except ValueError:
                rel_path = output_path
        else:
            rel_path = output_path
        
        link_html = f'[OK] Plot saved: <a href="../{rel_path}" target="_blank">{name}</a>'
        return HTML(link_html)
    
    return None


def save_dataframe(df, name: str, subdir: str = 'data', format: str = 'csv'):
    """
    Save DataFrame externally
    
    Args:
        df: pandas DataFrame
        name: Filename (without extension)
        subdir: Subdirectory under outputs/ (default: 'data')
        format: 'csv', 'parquet', or 'excel'
    
    Returns:
        Path to saved file
    """
    output_dir = Path('outputs') / subdir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    export_df = _prepare_dataframe_for_export(df)

    if format == 'csv':
        output_path = output_dir / f'{name}.csv'
        export_df.to_csv(output_path, index=False)
    elif format == 'parquet':
        output_path = output_dir / f'{name}.parquet'
        export_df.to_parquet(output_path, index=False)
    elif format == 'excel':
        output_path = output_dir / f'{name}.xlsx'
        export_df.to_excel(output_path, index=False)
    else:
        raise ValueError(f"Unknown format: {format}")
    
    print(f"[OK] DataFrame saved: {output_path}")
    return output_path


def display_sample(df, n: int = 20, title: Optional[str] = None):
    """
    Display sample of DataFrame (limits output size in notebook)
    
    Args:
        df: pandas DataFrame
        n: Number of rows to display
        title: Optional title to display
    """
    if title:
        display(HTML(f"<h4>{title}</h4>"))
    
    print(f"Showing {n} of {len(df):,} rows")
    display(df.head(n))
    
    if len(df) > n:
        print(f"... {len(df) - n:,} more rows")


def setup_notebook_output():
    """
    Configure notebook for clean output display
    Call this at the start of notebooks
    """
    import pandas as pd
    import warnings
    
    # Limit pandas output
    pd.set_option('display.max_rows', 20)
    pd.set_option('display.max_columns', 15)
    pd.set_option('display.width', 120)
    
    # Suppress common warnings
    warnings.filterwarnings('ignore', category=FutureWarning)
    warnings.filterwarnings('ignore', category=UserWarning)
    
    print("[OK] Notebook output configured")


# ---------------------------------------------------------------------------
# Console formatting helpers
# ---------------------------------------------------------------------------

def print_header(title: str, width: int = None) -> None:
    """Print a section header surrounded by '=' separator lines.

    Args:
        title: Heading text.
        width: Separator width. Defaults to the length of the title.
    """
    w = width if width is not None else len(title)
    sep = '=' * w + '=' * 2  # Add extra padding for visual separation
    print()
    print(sep)
    print(title)
    print(sep)
    print()


def print_subheader(title: str, width: int = None) -> None:
    """Print a sub-section header surrounded by '-' separator lines.

    Args:
        title: Heading text.
        width: Separator width. Defaults to the length of the title.
    """
    w = width if width is not None else len(title)
    sep = '-' * w
    print(sep)
    print(title)
    print(sep)


def print_separator(width: int = 70, char: str = '=') -> None:
    """Print a blank line followed by a separator line.

    Use this for a closing rule after a block of output, e.g. at the end
    of a section before the next one begins.

    Args:
        width: Length of the separator line (default 70).
        char:  Character used (default '=').
    """
    print()
    print(char * width)
